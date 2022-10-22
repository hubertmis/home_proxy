use std::borrow::Borrow;
use std::collections::BTreeMap;
use std::fmt::Write;
use std::net::UdpSocket;
use std::io;
use std::sync::{Arc, Mutex};

use async_coap::prelude::*;
use async_coap::{RespondableInboundContext, Error};
use async_coap::datagram::{DatagramLocalEndpoint, AllowStdUdpSocket};
use async_coap::message::MessageWrite;
use option::CONTENT_FORMAT;

use futures::prelude::*;

use openssl::error::ErrorStack;
use openssl::ssl::{SslAcceptor, SslMethod, SslRef};

use serde::Deserialize;

use clap::Parser;

const COAPS_PSK: &'static str = env!("COAPS_PSK");

/// zathome proxy server
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// IP address to bind to
    #[arg(short, long)]
    addr: Option<String>,

    // TODO: interface to bind to
}

fn receive_handler<T: RespondableInboundContext>(context: &T, secure: bool, metadata: &Arc<Mutex<std::sync::mpsc::Sender<u64>>>) -> Result<(),Error> {
    let msg = context.message();
    let uri = msg.options().extract_uri()?;
    let decoded_path = uri.raw_path().unescape_uri().skip_slashes().to_cow();

    let prj_tx = metadata;

    log::debug!("Receive handler security: {}", secure);

    match (msg.msg_code(), decoded_path.borrow()) {
        // Handle GET /test
        (MsgCode::MethodGet, "test") => context.respond(|msg_out| {
            msg_out.set_msg_code(MsgCode::SuccessContent);
            msg_out.insert_option(CONTENT_FORMAT, ContentFormat::TEXT_PLAIN_UTF8)?;
            write!(msg_out,"Successfully fetched {:?}!", uri.as_str())?;
            Ok(())
        }),

        (MsgCode::MethodPost, "prx/prj") => {
            #[derive(Deserialize)]
            struct PrjState {
                p: bool,
                d: Option<u32>,
            }

            // TODO: Verify destination address is max site local multicast
            //       Or source address is on link. Or security is on place

            let (prj_enabled, validity_time, msg_code) = match msg.content_format() {
                Some(ContentFormat::APPLICATION_CBOR) => {
                    let prj_state = serde_cbor::from_reader::<PrjState, _>(msg.payload());

                    if let Ok(prj_state) = prj_state {
                        (Some(prj_state.p), prj_state.d, MsgCode::SuccessContent)
                    } else {
                        (None, None, MsgCode::ClientErrorBadRequest)
                    }
                }
                _ => {
                    (None, None, MsgCode::ClientErrorUnsupportedMediaType)
                }
            };

            let validity_time = validity_time.unwrap_or(2 * 60 * 1000);

            if prj_enabled.unwrap_or(false) {
                prj_tx.lock().unwrap().send(u64::from(validity_time)).unwrap();
            } else {
                prj_tx.lock().unwrap().send(0).unwrap();
            }

            if msg.msg_type() == MsgType::Con {
                context.respond(|msg_out| {
                    msg_out.set_msg_code(msg_code);
                    Ok(())
                })
            } else {
                Ok(())
            }
        }

        // Handle GET /sd
        (MsgCode::MethodGet, "sd") => {
            #[derive(Deserialize)]
            struct Filter {
                name: Option<String>,
                r#type: Option<String>,
            }

            let filter_passed: bool;
            let msg_code;

            // TODO: Verify destination address is max site local multicast
            //       Or source address is on link. Or security is on place

            match msg.content_format() {
                Some(ContentFormat::APPLICATION_CBOR) => {
                    filter_passed = match serde_cbor::from_reader::<Filter, _>(msg.payload()) {
                        Ok(filter) => {
                            let name_passed = match filter.name.as_deref() {
                                None => true,
                                Some("prx") => true,
                                _ => false,
                            };

                            let type_passed = match filter.r#type.as_deref() {
                                None => true,
                                Some("proxy") => true,
                                _ => false,
                            };

                            if name_passed && type_passed {
                                msg_code = MsgCode::SuccessContent;
                            } else {
                                msg_code = MsgCode::ClientErrorBadRequest;
                            }

                            name_passed && type_passed
                        },
                        Err(_) => {
                            msg_code = MsgCode::ClientErrorBadRequest;
                            false
                        }
                    };
                }
                None => {
                    msg_code = MsgCode::SuccessContent;
                    filter_passed = true;
                }
                _ => {
                    msg_code = MsgCode::ClientErrorUnsupportedMediaType;
                    filter_passed = false;
                }
            }

            fn insert_payload(msg_out: &mut dyn MessageWrite) -> Result<(), Error> {
                msg_out.insert_option(CONTENT_FORMAT, ContentFormat::APPLICATION_CBOR)?;

                let mut ap_details = BTreeMap::new();
                ap_details.insert("type", "proxy");

                let mut data = BTreeMap::new();
                data.insert("prx", ap_details);

                serde_cbor::to_writer(msg_out, &data).unwrap();
                Ok(())
            }

            match msg.msg_type() {
                MsgType::Con => {
                    context.respond(|msg_out| {
                        msg_out.set_msg_code(msg_code);

                        if filter_passed {
                            insert_payload(msg_out)
                        } else {
                            Ok(())
                        }
                    })
                }
                MsgType::Non => {
                    // TODO random delay
                    if filter_passed {
                        context.respond(|msg_out| {
                            msg_out.set_msg_type(MsgType::Non);
                            // TODO: set_msg_id ?
                            msg_out.set_msg_code(msg_code);

                            insert_payload(msg_out)
                        })
                    } else {
                        Err(Error::ClientRequestError)
                    }
                }
                _ => Err(Error::ClientRequestError)
            }
        },

        // Handle unsupported methods
        (_, "test") | (_, ".well-known/core") => context.respond(|msg_out| {
           msg_out.set_msg_code(MsgCode::ClientErrorMethodNotAllowed);
            write!(msg_out,"Method \"{:?}\" Not Allowed", msg.msg_code())?;
            Ok(())
        }),

        // Everything else is a 4.04
        (_, _) => context.respond(|msg_out| {
            msg_out.set_msg_code(MsgCode::ClientErrorNotFound);
            write!(msg_out,"{:?} Not Found", uri.as_str())?;
            Ok(())
        }),
    }
}

fn psk_callback(_ssl: &mut SslRef, _identity: Option<&[u8]>, psk: &mut [u8]) -> Result<usize, ErrorStack> {
    let pass = COAPS_PSK.as_bytes();
    psk[0..pass.len()].copy_from_slice(pass);
    return Ok(pass.len());
}

fn ssl_acceptor() -> Result<SslAcceptor, io::Error> {
    let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::dtls()).unwrap();
    acceptor.set_psk_server_callback(psk_callback);
    acceptor.set_cipher_list("TLSv1.2:TLSv1.0")?;
    let acceptor = acceptor.build();
    Ok(acceptor)
}

#[tokio::main]
async fn main() {
    env_logger::init();
    log::debug!("Starting main");

    let args = Args::parse();

    let (prj_tx, prj_rx) = std::sync::mpsc::channel();
    let prj_tx = Arc::new(Mutex::new(prj_tx));

    let handle = tokio::runtime::Handle::current();
    let mut join_handles = Vec::new();

    let addr = if let Some(ref arg_addr) = args.addr {
            format!("{}:5683", arg_addr)
        } else {
            "[::]:5683".to_string()
        };
    let socket = AllowStdUdpSocket::bind(addr).expect("UDP bind failed");
    let endpoint = Arc::new(DatagramLocalEndpoint::new(socket));

    let unsecure_prj_tx = prj_tx.clone();
    join_handles.push(handle.spawn(endpoint
        .clone()
        .receive_loop_arc(move |context| receive_handler(context, false, &unsecure_prj_tx))
        .map(|_| unreachable!())
    ));

    let acceptor = ssl_acceptor().unwrap();
    let addr = if let Some(ref arg_addr) = args.addr {
            format!("{}:5684", arg_addr)
        } else {
            "[::]:5684".to_string()
        };

    let socket = async_coap_dtls::dtls::acceptor::DtlsAcceptorSocket::new(UdpSocket::bind(addr).unwrap(), acceptor);
    let endpoint = Arc::new(DatagramLocalEndpoint::new(socket));

    let secure_prj_tx = prj_tx.clone();
    join_handles.push(handle.spawn(endpoint
        .clone()
        .receive_loop_arc(move |context| receive_handler(context, true, &secure_prj_tx))
        .map(|_| unreachable!())
    ));

    let prj_rx_task = move || {
        async fn enable_yamaha() {
            let yamaha = yamahaec::basic::Device::new("sypialnia.local");
            let r = yamaha.set_input(None, "optical", None).await;
            log::debug!("Enabling yamaha: {:?}", r);
        }
        async fn disable_yamaha() {
            let yamaha = yamahaec::basic::Device::new("sypialnia.local");
            let r = yamaha.set_power(None, yamahaec::basic::Power::Standby).await;
            log::debug!("Disabling yamaha: {:?}", r);
        }

        let mut validity_ms;

        loop {
            let result = prj_rx.recv();

            if let Ok(data) = result {
                validity_ms = data;

                if validity_ms > 0 {
                    handle.spawn(enable_yamaha());
                } else {
                    continue;
                }

                loop {
                    let duration = core::time::Duration::from_millis(validity_ms);
                    let rx = prj_rx.recv_timeout(duration);

                    match rx {
                        Ok(data) => { 
                            validity_ms = data;

                            if validity_ms > 0 {
                                log::debug!("Extending timer by {} ms", validity_ms);
                            } else {
                                handle.spawn(disable_yamaha());
                                break;
                            }
                        }
                        Err(_) => {
                            log::debug!("Disabling yamaha on timeout");
                            handle.spawn(disable_yamaha());
                            break;
                        }
                    }
                }
            }
        }
    };
    std::thread::spawn(prj_rx_task);

    for jh in join_handles {
        jh.await.unwrap();
    }
}
