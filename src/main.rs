extern crate futures;
//extern crate native_tls;
//extern crate openssl;
//extern crate sonm;
//extern crate tokio;
//extern crate tokio_core;
//extern crate tokio_io;
//extern crate tokio_openssl;
//extern crate tokio_tls;
extern crate tower_grpc;
extern crate prost;
#[macro_use]
extern crate prost_derive;
extern crate tokio_core;
extern crate tower_h2;
extern crate tower_http;

use tokio_core::reactor::Core;
use tower_grpc::codegen::client::http;
use tokio_core::net::TcpStream;
use tower_h2::client::Connection;
use futures::Future;
use tower_grpc::Request;

//use grpc::RequestOptions;
//use openssl::ssl::{Ssl, SslConnectorBuilder, SslContext, SslMethod, SslStream, SslVerifyMode};
//use std::fs::File;
//use std::io;
//use std::io::Read;
//use std::net::ToSocketAddrs;
//use std::path::Path;
//use std::sync::Arc;
//use tls_api::TlsConnectorBuilder;
//use tokio::net::TcpStream;
//use tokio::runtime::current_thread::Runtime;
//use tokio_core::reactor::Core;
//use tokio_openssl::{ConnectConfigurationExt, SslAcceptorExt, SslConnectorExt};
//use sonm::TokenManagement;

mod sonm {
    include!(concat!(env!("OUT_DIR"), "/sonm.rs"));
}

//fn openssl2io(e: openssl::ssl::Error) -> io::Error {
//    io::Error::new(io::ErrorKind::Other, e)
//}

fn main() {
    let mut core = Core::new().unwrap();
    let reactor = core.handle();

    let addr = "127.0.0.1:15030".parse().unwrap();
    let uri: http::Uri = format!("http://localhost:15030").parse().unwrap();

    let future = TcpStream::connect(&addr, &reactor)
        .and_then(move |socket| {
            // Bind the HTTP/2.0 connection
            Connection::handshake(socket, reactor)
                .map_err(|_| panic!("failed HTTP/2.0 handshake"))
        })
        .map(move |conn| {
            use sonm::client::TokenManagement;

            let conn = tower_http::add_origin::Builder::new()
                .uri(uri)
                .build(conn)
                .unwrap();

            TokenManagement::new(conn)
        })
        .and_then(|mut client| {
            use sonm::Empty;

            client.balance(Request::new(Empty{})).map_err(|e| panic!("gRPC request failed; err={:?}", e))
        })
        .and_then(|response| {
            println!("RESPONSE = {:?}", response);
            Ok(())
        })
        .map_err(|e| {
            println!("ERR = {:?}", e);
        });

    core.run(future).unwrap();

//    let cert_path = Path::new("/Users/esafronov/go/src/github.com/sonm-io/core");
//
//    let cert = cert_path.join("cert.pem");
//    let key = cert_path.join("key.pem");

//    NOT WORKS!
//    let mut builder = SslConnectorBuilder::new(SslMethod::tls()).unwrap();
//    builder.set_cipher_list("DEFAULT").unwrap();
//    builder.set_certificate_file(cert, openssl::x509::X509_FILETYPE_PEM).unwrap();
//    builder.set_private_key_file(key, openssl::x509::X509_FILETYPE_PEM).unwrap();
//    builder.set_verify_callback(openssl::ssl::SSL_VERIFY_NONE, |v, ctx| {
//        let cert = ctx.current_cert().unwrap();
//
//        let subject_names = cert.subject_alt_names().unwrap()
//            .iter()
//            .map(|n| n.dnsname().unwrap().to_string())
//            .collect::<Vec<_>>();
//        println!("-> {} {:?} {} {:?}", v, ctx.error(), cert.not_before(), subject_names);
//        true
//    });
//    let connector = sonm::tls::TlsConnectorBuilder(builder);
//    let conn = connector.build().unwrap();
//
//    let tls_option = httpbis::ClientTlsOption::Tls("0x8125721C2413d99a33E351e1F6Bb4e56b6b633FD@127.0.0.1:15030".into(), Arc::new(conn));
//    let client = grpc::Client::new_expl(&addr, "0x8125721C2413d99a33E351e1F6Bb4e56b6b633FD", tls_option, Default::default()).unwrap();
////    let client = sonm::TokenManagementClient::with_client(client);
//    let client = sonm::TokenManagementClient::new_plain("::1", 15030, Default::default()).unwrap();
//
//    let resp = client.balance(RequestOptions::new(), sonm::Empty::new()).wait();
//    println!("Balance: {:?}", resp);

//    IT WORKS!
//    let mut runtime = Runtime::new().unwrap();
//
//
//    let sock = TcpStream::connect(&addr);
//    let data = sock.and_then(move |sock| {
//        let mut builder = SslConnector::builder(SslMethod::tls()).unwrap();
//        builder.set_cipher_list("DEFAULT").unwrap();
//        builder.set_certificate_file(cert, SslFiletype::PEM).unwrap();
//        builder.set_private_key_file(key, SslFiletype::PEM).unwrap();
//        builder.set_verify_callback(SslVerifyMode::NONE, |v, ctx| {
//            let cert = ctx.current_cert().unwrap();
//
//            let sns = cert.subject_alt_names().unwrap().iter().map(|n| n.dnsname().unwrap().to_string()).collect::<Vec<_>>();
//            println!("5 {} {:?} {} {:?} {:?}", v, ctx.error(), cert.not_before(), cert.serial_number().get(), sns);
//            true
//        });
//        let connector = builder.build();
//        let mut cfg = connector.configure().unwrap();
//        cfg.set_verify_hostname(false);
//        println!("4");
//        cfg.connect_async("0x8125721C2413d99a33E351e1F6Bb4e56b6b633FD@127.0.0.1:15030", sock).map_err(openssl2io)
//    }).and_then(|socket| {
//        println!("5");
//        tokio::io::write_all(socket, b"GET / HTTP.0\r\n\r\n")
//    }).and_then(|(sock, _)| {
//        println!("6");
//        tokio::io::flush(sock)
//    }).and_then(|sock| {
//        println!("7");
//        tokio::io::read_to_end(sock, Vec::new())
//    });
//
//    let r = runtime.block_on(data).unwrap();
//    println!("{:?}", r);
}
