//! A Proxy Connector crate for Hyper based applications
//!
//! # Example
//! ```rust,no_run
//! extern crate hyper;
//! extern crate hyper_proxy;
//! extern crate futures;
//! extern crate tokio_core;
//!
//! use hyper::{Chunk, Client, Request, Method, Uri};
//! use hyper::client::HttpConnector;
//! use hyper::header::Basic;
//! use futures::{Future, Stream};
//! use hyper_proxy::{Proxy, ProxyConnector, Intercept};
//! use tokio_core::reactor::Core;
//!
//! fn main() {
//!     let mut core = Core::new().unwrap();
//!     let handle = core.handle();
//!
//!     let proxy = {
//!         let proxy_uri = "http://my-proxy:8080".parse().unwrap();
//!         let mut proxy = Proxy::new(Intercept::All, proxy_uri);
//!         proxy.set_authorization(Basic {
//!                                    username: "John Doe".into(),
//!                                    password: Some("Agent1234".into()),
//!                                });
//!         let connector = HttpConnector::new(4, &handle);
//!         let proxy_connector = ProxyConnector::from_proxy(connector, proxy).unwrap();
//!         proxy_connector
//!     };
//!
//!     // Connecting to http will trigger regular GETs and POSTs.
//!     // We need to manually append the relevant headers to the request
//!     let uri: Uri = "http://my-remote-website.com".parse().unwrap();
//!     let mut req = Request::new(Method::Get, uri.clone());
//!     if let Some(headers) = proxy.http_headers(&uri) {
//!         req.headers_mut().extend(headers.iter());
//!         req.set_proxy(true);
//!     }
//!     let client = Client::configure().connector(proxy).build(&handle);
//!     let fut_http = client.request(req)
//!         .and_then(|res| res.body().concat2())
//!         .map(move |body: Chunk| ::std::str::from_utf8(&body).unwrap().to_string());
//!
//!     // Connecting to an https uri is straightforward (uses 'CONNECT' method underneath)
//!     let uri = "https://my-remote-websitei-secured.com".parse().unwrap();
//!     let fut_https = client
//!         .get(uri)
//!         .and_then(|res| res.body().concat2())
//!         .map(move |body: Chunk| ::std::str::from_utf8(&body).unwrap().to_string());
//!
//!     let futs = fut_http.join(fut_https);
//!
//!     let (_http_res, _https_res) = core.run(futs).unwrap();
//! }
//! ```

#![deny(missing_docs)]

extern crate bytes;
#[macro_use]
extern crate futures;
extern crate hyper;
#[cfg(test)]
extern crate hyper_tls;
extern crate headers;
#[cfg(feature = "tls")]
extern crate native_tls;
extern crate tokio_core;
extern crate tokio_io;
#[cfg(feature = "tls")]
extern crate tokio_tls;

mod tunnel;
mod stream;

use std::any::Any;
use std::fmt;
use std::io;
use std::sync::{Arc, Mutex};
use futures::Future;
use hyper::client::connect::{Connect, Destination, Connected};
use headers::{Authorization, Header, Headers, ProxyAuthorization, Scheme};
#[cfg(feature = "tls")]
use tokio_tls::TlsConnector as AsyncTlsConnector;
use native_tls::TlsConnector;
use stream::ProxyStream;

/// The Intercept enum to filter connections
#[derive(Debug, Clone)]
pub enum Intercept {
    /// All incoming connection will go through proxy
    All,
    /// Only http connections will go through proxy
    Http,
    /// Only https connections will go through proxy
    Https,
    /// No connection will go through this proxy
    None,
    /// A custom intercept
    Custom(Custom),
}

/// A Custom struct to proxy custom uris
#[derive(Clone)]
pub struct Custom(Arc<Fn(&Destination) -> bool + Send + Sync>);

impl fmt::Debug for Custom {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "_")
    }
}

impl<F: Fn(&Destination) -> bool + Send + Sync + 'static> From<F> for Custom {
    fn from(f: F) -> Custom {
        Custom(Arc::new(f))
    }
}

impl Intercept {
    /// A function to check if given `Destination` is proxied
    pub fn matches(&self, dst: &Destination) -> bool {
        match (self, dst.scheme()) {
            (&Intercept::All, _)
            | (&Intercept::Http, "http")
            | (&Intercept::Https, "https") => true,
            (&Intercept::Custom(Custom(ref f)), _) => f(dst),
            _ => false,
        }
    }
}

impl<F: Fn(&Destination) -> bool + Send + Sync + 'static> From<F> for Intercept {
    fn from(f: F) -> Intercept {
        Intercept::Custom(f.into())
    }
}

/// A Proxy strcut
#[derive(Clone, Debug)]
pub struct Proxy {
    intercept: Intercept,
    headers: Arc<Mutex<Headers>>,
    dst: Destination,
}

impl Proxy {
    /// Create a new `Proxy`
    pub fn new<I: Into<Intercept>>(intercept: I, dst: Destination) -> Proxy {
        Proxy {
            intercept: intercept.into(),
            dst,
            headers: Arc::new(Mutex::new(Headers::new())),
        }
    }

    /// Set `Proxy` authorization
    pub fn set_authorization<S: Scheme + Any>(&mut self, scheme: S) {
        let mut headers = self.headers.lock().unwrap();
        match self.intercept {
            Intercept::Http => headers.set(Authorization(scheme)),
            Intercept::Https => headers.set(ProxyAuthorization(scheme)),
            _ => {
                headers.set(ProxyAuthorization(scheme.clone()));
                headers.set(Authorization(scheme));
            }
        }
    }

    /// Set a custom header
    pub fn set_header<H: Header>(&mut self, header: H) {
        self.headers.lock().unwrap().set(header);
    }

    /// Get current intercept
    pub fn intercept(&self) -> &Intercept {
        &self.intercept
    }

    /// Get current `Headers` which must be sent to proxy
    pub fn headers(&self) -> Headers {
        self.headers.lock().unwrap().clone()
    }

    /// Get proxy uri
    pub fn uri(&self) -> &Destination {
        &self.dst
    }
}

/// A wrapper around `Proxy`s with a connector.
pub struct ProxyConnector<C> {
    proxies: Vec<Proxy>,
    connector: C,
    #[cfg(feature = "tls")]
    tls: Option<TlsConnector>,
    #[cfg(not(feature = "tls"))]
    tls: Option<()>,
}

impl<C: fmt::Debug> fmt::Debug for ProxyConnector<C> {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "ProxyConnector {}{{ proxies: {:?}, connector: {:?} }}",
            if self.tls.is_some() {
                ""
            } else {
                "(unsecured)"
            },
            self.proxies,
            self.connector
        )
    }
}

impl<C> ProxyConnector<C> {
    /// Create a new secured Proxies
    #[cfg(feature = "tls")]
    pub fn new(connector: C) -> Result<Self, io::Error> {
        let tls = TlsConnector::builder().build()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        Ok(ProxyConnector {
            proxies: Vec::new(),
            connector,
            tls: Some(tls)
        })
    }

    /// Create a new unsecured Proxy
    pub fn unsecured(connector: C) -> Self {
        ProxyConnector {
            proxies: Vec::new(),
            connector: connector,
            tls: None,
        }
    }

    /// Create a proxy connector and attach a particular proxy
    #[cfg(feature = "tls")]
    pub fn from_proxy(connector: C, proxy: Proxy) -> Result<Self, io::Error> {
        let mut c = ProxyConnector::new(connector)?;
        c.proxies.push(proxy);
        Ok(c)
    }

    /// Create a proxy connector and attach a particular proxy
    pub fn from_proxy_unsecured(connector: C, proxy: Proxy) -> Self {
        let mut c = ProxyConnector::unsecured(connector);
        c.proxies.push(proxy);
        c
    }

    /// Change proxy connector
    pub fn with_connector<CC>(self, connector: CC) -> ProxyConnector<CC> {
        ProxyConnector {
            connector: connector,
            proxies: self.proxies,
            tls: self.tls,
        }
    }

    /// Set or unset tls when tunneling
    #[cfg(feature = "tls")]
    pub fn set_tls(&mut self, tls: Option<TlsConnector>) {
        self.tls = tls;
    }

    /// Get the current proxies
    pub fn proxies(&self) -> &[Proxy] {
        &self.proxies
    }

    /// Add a new additional proxy
    pub fn add_proxy(&mut self, proxy: Proxy) {
        self.proxies.push(proxy);
    }

    /// Extend the list of proxies
    pub fn extend_proxies<I: IntoIterator<Item = Proxy>>(&mut self, proxies: I) {
        self.proxies.extend(proxies)
    }

    /// Get http headers for a matching uri
    ///
    /// These headers must be appended to the hyper Request for the proxy to work properly.
    /// This is needed only for http requests.
    pub fn http_headers(&self, uri: &Destination) -> Option<Headers> {
        if uri.scheme() != "http" {
            return None;
        }
        self.match_proxy(uri).map(|p| p.headers())
    }

    fn match_proxy(&self, uri: &Destination) -> Option<&Proxy> {
        self.proxies.iter().find(|p| p.intercept.matches(uri))
    }
}

impl<C> Connect for ProxyConnector<C> where C: Connect, C::Error: 'static, C::Future: 'static {
    type Transport = ProxyStream<C::Transport>;
    type Error = io::Error;
    type Future = Box<Future<Item = (ProxyStream<C::Transport>, Connected), Error = Self::Error> + Send>;

    fn connect(&self, dst: Destination) -> Self::Future {
        if let Some(ref p) = self.match_proxy(&dst) {
            if dst.scheme() == "https" {
                let host = dst.host().to_owned();
                let port = dst.port().unwrap_or(443);
                let tunnel = tunnel::Tunnel::new(&host, port, &p.headers());
                let proxy_stream = self.connector
                    .connect(p.dst.clone())
                    .map_err(io_err)
                    .and_then(move |(io, connected)| tunnel.with_stream(io)
                        .map(|t| (t, connected)));
                match self.tls.clone() {
                    #[cfg(feature = "tls")]
                    Some(tls) => {
                        let tls = AsyncTlsConnector::from(tls);
                        Box::new(
                            proxy_stream
                                .and_then(move |(io, connected)|
                                    tls.connect(&host, io)
                                        .map(|c| (c, connected))
                                        .map_err(io_err))
                                .map(|(s, connected)| (ProxyStream::Secured(s), connected))
                        )
                    },
                    #[cfg(not(feature = "tls"))]
                    Some(_) => panic!("hyper-proxy was not built with TLS support"),

                    None => Box::new(proxy_stream
                        .map(|(s, connected)| (ProxyStream::Regular(s), connected))),
                }
            } else {
                // without TLS, there is absolutely zero benefit from tunneling, as the proxy can
                // read the plaintext traffic. Thus, tunneling is just restrictive to the proxies
                // resources.
                Box::new(
                    self.connector
                        .connect(p.dst.clone())
                        .map_err(io_err)
                        .map(|(s, connected)| (ProxyStream::Regular(s), connected)),
                )
            }
        } else {
            Box::new(self.connector
                .connect(dst)
                .map_err(io_err)
                .map(|(s, connected)| (ProxyStream::Regular(s), connected)))
        }
    }
}

#[inline]
fn io_err<E: Into<Box<::std::error::Error + Send + Sync>>>(e: E) -> io::Error {
    io::Error::new(io::ErrorKind::Other, e)
}
