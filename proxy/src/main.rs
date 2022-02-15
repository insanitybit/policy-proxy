#![feature(ip)]
#![allow(warnings)]

use biscuit_auth as biscuit;
use futures::future::BoxFuture;

use std::convert::Infallible;
use std::net::SocketAddr;
use std::str::{FromStr, Utf8Error};
use biscuit::Biscuit;
use biscuit_auth::builder::Rule;
use biscuit_auth::PublicKey;
use hyper::{Body, Request, Response, Server, StatusCode};
use hyper::server::conn::{AddrStream, Http};
use hyper::service::{make_service_fn, service_fn};
use hyper::Method;
use eyre::{ErrReport, Result};
use hyper::header::{HOST, PROXY_AUTHORIZATION};
use hyper::upgrade::Upgraded;
use tokio::net::{TcpListener, TcpStream};
use tokio::pin;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use trust_dns_resolver::{config::{
    NameServerConfigGroup,
    ResolverConfig,
    ResolverOpts,
}, error::ResolveError, proto::{
    error::ProtoError as ProtocolError,
    rr::rdata::SRV,
}, Name, TokioAsyncResolver, AsyncResolver};
use trust_dns_resolver::lookup_ip::LookupIp;
use std::net::IpAddr;
use std::os::unix::io::RawFd;
use std::os::unix::prelude::AsRawFd;
use std::sync::Arc;
use std::time::Duration;
use futures::future;
use nix::errno::Errno;
use nix::fcntl::{OFlag, SpliceFFlags};
use tracing::{Instrument, instrument};
use tokio::sync::oneshot;
use tokio::sync::oneshot::error::TryRecvError;

async fn resolve_lowest_pri(resolver: &TokioAsyncResolver, name: Name) -> Result<Option<IpAddr>> {
    let srvs = resolver.lookup_ip(name.clone()).await?;

    Ok(srvs.iter().next())
}


/// Handle server-side I/O after HTTP upgraded.
#[tracing::instrument]
async fn server_upgraded_io(mut src_fd: RawFd, mut dst_fd: RawFd) -> Result<()> {
    tracing::info!(message="creating pipe");

    let (read_pipe, write_pipe) = nix::unistd::pipe2(
        OFlag::O_NONBLOCK
    )?;
    tracing::info!(message="copying bytes");

    loop {
        tokio::task::yield_now().await;
        let r = nix::fcntl::splice(
            src_fd,
            None,
            write_pipe.as_raw_fd(),
            None,
            4096,
            SpliceFFlags::SPLICE_F_NONBLOCK | SpliceFFlags::SPLICE_F_MOVE | SpliceFFlags::SPLICE_F_MORE,
        );

        match r {
            Ok(1..) => tracing::info!(message="Copied data from", r=?r),
            Ok(_) => {
                tracing::debug!("src -> write Ok(0)");
                break;
            }
            Err(e) => {
                tracing::warn!(message="Failed to copy data from", error=?e);
            }
        }
        tokio::task::yield_now().await;
        let r = nix::fcntl::splice(
            read_pipe.as_raw_fd(),
            None,
            dst_fd,
            None,
            4096,
            SpliceFFlags::SPLICE_F_NONBLOCK | SpliceFFlags::SPLICE_F_MOVE | SpliceFFlags::SPLICE_F_MORE,
        );

        match r {
            Ok(1..) => tracing::info!(message="Copied data to", r=?r),
            Ok(_) => {
                tracing::debug!("read -> dst Ok(0)");
                break;
            }
            Err(e) => {
                tracing::warn!(message="Failed to copy data to", error=?e);
            }
        }
    }

    tracing::info!("Joined");
    Ok(())
}


fn authorize_host(host: &str, token: &Biscuit) -> Result<(), biscuit::error::Token> {
    let mut authorizer = token.authorizer()?;
    let mut rule: Rule = r#"
    allow if
      resource($host),
      operation("connect")
    "#.try_into()?;

    rule.set("host", host)?;
    authorizer.add_rule(rule)?;
    authorizer.allow()?;

    authorizer.authorize()?;

    Ok(())
}

/// Our server HTTP handler to initiate HTTP upgrades.
#[instrument(skip(public_key, req))]
async fn server_upgrade(rx: Arc<tokio::sync::Mutex<Option<TcpStream>>>, resolver: TokioAsyncResolver, public_key: PublicKey, mut req: Request<Body>) -> Result<Response<Body>> {
    tracing::info!(message="upgrading");
    let mut res = Response::new(Body::empty());

    // let token = match req.headers().get(PROXY_AUTHORIZATION) {
    //     Some(host) => host.as_bytes(),
    //     None => {
    //         *res.status_mut() = StatusCode::BAD_REQUEST;
    //         return Ok(res);
    //     }
    // };
    //
    // let biscuit = match Biscuit::from_base64(token, |_| public_key) {
    //     Ok(biscuit) => biscuit,
    //     Err(e) => {
    //         *res.status_mut() = StatusCode::BAD_REQUEST;
    //         return Ok(res);
    //     }
    // };

    let host = match req.headers().get(HOST) {
        Some(host) => host.as_bytes(),
        None => {
            *res.status_mut() = StatusCode::BAD_REQUEST;
            return Ok(res);
        }
    };

    let host = match std::str::from_utf8(host) {
        Ok(host) => { host }
        Err(e) => {
            *res.status_mut() = StatusCode::BAD_REQUEST;
            return Ok(res);
        }
    };

    let host = match host.rfind(":") {
        None => host,
        Some(i) => &host[..i],
    };

    tracing::info!(message="routing to host", host=%host);
    // validate that it's OK for this client to talk to this host
    // todo: authorize port?
    // authorize_host(host, &biscuit)?;

    let then = std::time::Instant::now();
    let response = resolve_lowest_pri(
        &resolver,
        Name::from_str(host).unwrap(),
    ).await.unwrap().unwrap();

    let now = std::time::Instant::now();
    tracing::info!(message="resolving host", time=%now.duration_since(then).as_millis());

    // Only ever route to external addresses
    // if !response.is_global() {
    //     todo!()
    // }
    tracing::info!(message="Opening connection", ip_addr=?response);
    let socket_addr: SocketAddr = SocketAddr::from((response, 443));
    // connect to the host

    let then = std::time::Instant::now();

    let downstream = match TcpStream::connect(socket_addr).await {
        Ok(stream) => stream,
        Err(err) => {
            // todo: Do better error handling!
            tracing::error!(message="downstream", error=?err);
            *res.status_mut() = StatusCode::BAD_REQUEST;
            return Ok(res);
        }
    };

    let now = std::time::Instant::now();
    tracing::info!(message="connected to host", time=%now.duration_since(then).as_millis());

    tokio::task::spawn(async move {
        let upgraded = loop {
            let guard = rx.clone();
            let mut guard = guard.lock().await;
            match guard.take() {
                None => {
                    tracing::info!("not ready");
                    tokio::task::yield_now().await;
                }
                Some(upgraded) => { break upgraded; }
            }
        };

        let upgraded = upgraded.as_raw_fd();
        let downstream = downstream.as_raw_fd();

        let src_dst = async move {
            let then = std::time::Instant::now();
            server_upgraded_io(upgraded, downstream).await;
            let now = std::time::Instant::now();
            tracing::info!(message="Completed upgrade io for src_dst", time=%now.duration_since(then).as_millis());
        };

        let dst_src = async move {
            let then = std::time::Instant::now();
            server_upgraded_io(downstream, upgraded).await;
            let now = std::time::Instant::now();
            tracing::info!(message="Completed upgrade io for dst_src", time=%now.duration_since(then).as_millis());
        };

        let then = std::time::Instant::now();

        tracing::info!("joining");
        futures::future::join(src_dst,
                              dst_src).instrument(tracing::info_span!("join")).await;
        let now = std::time::Instant::now();
        tracing::info!(message="Completed upgrade io for src_dst dst_src", time=%now.duration_since(then).as_millis());
    }.instrument(tracing::info_span!("upgraded_io")));

    *res.status_mut() = StatusCode::from_u16(200).unwrap();

    *res.body_mut() = Body::from("Connection Established");

    Ok(res)
}


fn handle(rx: Arc<tokio::sync::Mutex<Option<TcpStream>>>, resolver: TokioAsyncResolver, public_key: PublicKey, req: Request<Body>) -> BoxFuture<'static, Result<Response<Body>>> {
    Box::pin(async move {
        server_upgrade(rx, resolver, public_key, req).await
    })
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let addr: SocketAddr = ([0, 0, 0, 0], 8080).into();

    tracing_subscriber::fmt::init();
    tracing::info!("running");

    let mut tcp_listener = TcpListener::bind(addr).await?;
    let public_key: PublicKey = PublicKey::from_bytes(&[0; 32])?;
    let resolver = TokioAsyncResolver::tokio_from_system_conf().unwrap();
    loop {
        let (tcp_stream, _) = tcp_listener.accept().await?;
        tracing::info!("Accepted");
        let resolver = resolver.clone();

        tokio::task::spawn(async move {
            let rx = Arc::new(tokio::sync::Mutex::new(None));
            let _rx = rx.clone();
            let parts = Http::new()
                .serve_connection(
                    tcp_stream, service_fn(move |req| handle(_rx.clone(), resolver.clone(), public_key, req)),
                )
                .without_shutdown()
                .await.unwrap(); // todo
            *rx.lock().await = Some(parts.io);
        }.instrument(tracing::info_span!("accept")));
    }
}