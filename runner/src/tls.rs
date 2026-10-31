//! QA Harness HTTP/1.1 TLS transport: bounded messages, pinned test certificate,
//! exact DNS authority routed to an owned loopback socket.
use http::{Request, Response};
use rustls::pki_types::{PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig, StreamOwned};
use std::{
    io::{self, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

pub struct TlsServer {
    host: &'static str,
    address: SocketAddr,
    cert_pem: String,
    cert_der: Vec<u8>,
    #[allow(dead_code)]
    client: Arc<ClientConfig>,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

fn client_config(roots: RootCertStore) -> Result<ClientConfig> {
    Ok(
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()?
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

fn socket(address: SocketAddr) -> io::Result<TcpStream> {
    let s = TcpStream::connect_timeout(&address, Duration::from_secs(15))?;
    s.set_read_timeout(Some(Duration::from_secs(15)))?;
    s.set_write_timeout(Some(Duration::from_secs(15)))?;
    Ok(s)
}

fn read_head(stream: &mut impl Read) -> io::Result<(Vec<u8>, usize)> {
    let mut bytes = Vec::new();
    loop {
        let mut chunk = [0; 2048];
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "peer closed before HTTP headers",
            ));
        }
        bytes.extend_from_slice(&chunk[..n]);
        if bytes.len() > 65536 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "message too large",
            ));
        }
        if let Some(i) = bytes.windows(4).position(|s| s == b"\r\n\r\n") {
            return Ok((bytes, i + 4));
        }
    }
}

fn read_body(
    stream: &mut impl Read,
    bytes: &[u8],
    end: usize,
    headers: &[httparse::Header<'_>],
) -> Result<Vec<u8>> {
    if headers
        .iter()
        .any(|h| h.name.eq_ignore_ascii_case("transfer-encoding"))
    {
        return Err("qa transport does not accept transfer coding".into());
    }
    let lengths: Vec<_> = headers
        .iter()
        .filter(|h| h.name.eq_ignore_ascii_case("content-length"))
        .collect();
    if lengths.len() > 1 {
        return Err("duplicate content-length".into());
    }
    let length = match lengths.first() {
        Some(h) => std::str::from_utf8(h.value)?.parse::<usize>()?,
        None => 0,
    };
    if length > 262144 || bytes.len() - end > length {
        return Err("invalid message length".into());
    }
    let mut body = bytes[end..].to_vec();
    let remaining = length - body.len();
    stream.take(remaining as u64).read_to_end(&mut body)?;
    if body.len() != length {
        return Err("truncated HTTP message".into());
    }
    Ok(body)
}

fn serve(
    stream: &mut (impl Read + Write),
    host: &str,
    handler: &impl Fn(Request<Vec<u8>>) -> Response<Vec<u8>>,
) -> Result<()> {
    let (bytes, end) = read_head(stream)?;
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut parsed = httparse::Request::new(&mut headers);
    if !parsed.parse(&bytes)?.is_complete() {
        return Err("incomplete HTTP request".into());
    }
    let hosts: Vec<_> = parsed
        .headers
        .iter()
        .filter(|h| h.name.eq_ignore_ascii_case("host"))
        .collect();
    if hosts.len() != 1 || hosts[0].value != host.as_bytes() {
        return Err("unexpected authority".into());
    }
    let path = parsed.path.ok_or("missing target")?;
    if !path.starts_with('/') || path.starts_with("//") {
        return Err("unexpected request-target".into());
    }
    let body = read_body(stream, &bytes, end, parsed.headers)?;
    let mut builder = Request::builder()
        .method(parsed.method.ok_or("missing method")?)
        .uri(format!("https://{host}{path}"));
    for h in parsed.headers {
        builder = builder.header(h.name, h.value)
    }
    let response = handler(builder.body(body)?);
    write!(
        stream,
        "HTTP/1.1 {} {}\r\nContent-Length: {}\r\nConnection: close\r\n",
        response.status().as_u16(),
        response.status().canonical_reason().unwrap_or("Response"),
        response.body().len()
    )?;
    for (name, value) in response.headers() {
        write!(stream, "{}: {}\r\n", name, value.to_str()?)?
    }
    stream.write_all(b"\r\n")?;
    stream.write_all(response.body())?;
    stream.flush()?;
    Ok(())
}

impl TlsServer {
    pub fn start(
        host: &'static str,
        handler: impl Fn(Request<Vec<u8>>) -> Response<Vec<u8>> + Send + 'static,
    ) -> Result<Self> {
        let certified = rcgen::generate_simple_self_signed(vec![host.into()])?;
        let cert_pem = certified.cert.pem();
        let cert_der = certified.cert.der().as_ref().to_vec();
        let cert = certified.cert.der().clone();
        let key = PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der());
        let config = Arc::new(
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()?
                .with_no_client_auth()
                .with_single_cert(vec![cert.clone()], key.into())?,
        );
        let mut roots = RootCertStore::empty();
        roots.add(cert)?;
        let client = Arc::new(client_config(roots)?);
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
        let address = listener.local_addr()?;
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = stop.clone();
        let worker = thread::spawn(move || {
            while !stopping.load(Ordering::Acquire) {
                let Ok((tcp, _)) = listener.accept() else {
                    break;
                };
                if stopping.load(Ordering::Acquire) {
                    break;
                }
                if tcp.set_read_timeout(Some(Duration::from_secs(15))).is_err()
                    || tcp.set_write_timeout(Some(Duration::from_secs(15))).is_err()
                {
                    continue;
                }
                let Ok(conn) = rustls::ServerConnection::new(config.clone()) else {
                    break;
                };
                let mut stream = StreamOwned::new(conn, tcp);
                let _ = serve(&mut stream, host, &handler);
            }
        });
        Ok(Self {
            host,
            address,
            cert_pem,
            cert_der,
            client,
            stop,
            worker: Some(worker),
        })
    }

    pub fn address(&self) -> SocketAddr {
        self.address
    }

    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    #[allow(dead_code)]
    pub fn cert_der(&self) -> &[u8] {
        &self.cert_der
    }

    pub fn send_external(
        address: SocketAddr,
        host: &'static str,
        cert_der: &[u8],
        request: &Request<Vec<u8>>,
    ) -> Result<Response<Vec<u8>>> {
        Self::send_external_with(address, host, cert_der, request, true)
    }

    pub fn send_held_external(
        address: SocketAddr,
        host: &'static str,
        cert_der: &[u8],
        request: &Request<Vec<u8>>,
    ) -> Result<Response<Vec<u8>>> {
        Self::send_external_with(address, host, cert_der, request, false)
    }

    pub fn send_external_with(
        address: SocketAddr,
        host: &'static str,
        cert_der: &[u8],
        request: &Request<Vec<u8>>,
        close: bool,
    ) -> Result<Response<Vec<u8>>> {
        if request.uri().scheme_str() != Some("https")
            || request.uri().authority().map(|a| a.as_str()) != Some(host)
        {
            return Err("qa egress admission refused target".into());
        }
        let mut roots = RootCertStore::empty();
        roots.add(rustls::pki_types::CertificateDer::from(cert_der.to_vec()))?;
        let config = Arc::new(client_config(roots)?);
        let conn = rustls::ClientConnection::new(config, ServerName::try_from(host)?)?;
        let mut stream = StreamOwned::new(conn, socket(address)?);
        if close {
            write!(
                stream,
                "{} {} HTTP/1.1\r\nHost: {}\r\nContent-Length: {}\r\nConnection: close\r\n",
                request.method(),
                request
                    .uri()
                    .path_and_query()
                    .map(|p| p.as_str())
                    .unwrap_or("/"),
                host,
                request.body().len()
            )?;
        } else {
            write!(
                stream,
                "{} {} HTTP/1.1\r\nHost: {}\r\nContent-Length: {}\r\n",
                request.method(),
                request
                    .uri()
                    .path_and_query()
                    .map(|p| p.as_str())
                    .unwrap_or("/"),
                host,
                request.body().len()
            )?;
        }
        for (name, value) in request.headers() {
            if name == "host" || name == "content-length" || name == "connection" {
                continue;
            }
            write!(stream, "{}: {}\r\n", name, value.to_str()?)?;
        }
        stream.write_all(b"\r\n")?;
        stream.write_all(request.body())?;
        stream.flush()?;
        let (bytes, end) = read_head(&mut stream)?;
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut parsed = httparse::Response::new(&mut headers);
        if !parsed.parse(&bytes)?.is_complete() {
            return Err("incomplete HTTP response".into());
        }
        let body = read_body(&mut stream, &bytes, end, parsed.headers)?;
        let mut builder = Response::builder().status(parsed.code.ok_or("missing status")?);
        for h in parsed.headers {
            builder = builder.header(h.name, h.value)
        }
        Ok(builder.body(body)?)
    }

    pub fn send(&self, request: &Request<Vec<u8>>) -> Result<Response<Vec<u8>>> {
        Self::send_external_with(self.address, self.host, &self.cert_der, request, false)
    }
}

impl Drop for TlsServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let _ = TcpStream::connect_timeout(&self.address, Duration::from_secs(1));
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
