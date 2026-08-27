//! A real rendezvous, on a real socket, for the integration tests.
//!
//! The tests below do not stub the transport. `contracts/docs/trust-boundaries.md`
//! §2's guarantee is about what happens when hostile bytes arrive on a socket,
//! and a test that hands them to a parser function directly is not testing that.

#![allow(dead_code)]

pub mod keys;

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

pub use keys::TestKey;
use twinvpn_rendezvous as rz;
use twinvpn_service_common as svc;

/// A running service and the address it is listening on.
pub struct Harness {
    /// Where to connect.
    pub addr: SocketAddr,
    /// The shared state, so a test can assert on the tables directly.
    pub shared: Arc<rz::server::Shared>,
    /// The server's raw public key, for a client to pin.
    pub server_spki: Vec<u8>,
    shutdown: Arc<svc::shutdown::Shutdown>,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
}

/// Starts a rendezvous bound to `host:0`.
///
/// The slowloris bound is shortened to 300 ms so a test that deliberately
/// stalls a frame does not spend the production five seconds waiting for the
/// service to give up on it.
pub async fn start(host: IpAddr) -> Harness {
    start_with(host, |mut c| {
        c.frame_read_timeout = std::time::Duration::from_millis(300);
        c
    })
    .await
}

/// Starts a rendezvous with the configuration adjusted by `f`.
pub async fn start_with(
    host: IpAddr,
    f: impl FnOnce(rz::config::RendezvousConfig) -> rz::config::RendezvousConfig,
) -> Harness {
    // A fresh server identity per harness, so two concurrently running tests
    // cannot share a key and a test can never depend on one that is checked in.
    let server_key = TestKey::generate();
    let key_path = server_key.write_pem(&format!(
        "rz-server-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let env = svc::config::MapEnv::new()
        .with(rz::config::keys::TLS_CERT, "Cargo.toml")
        .with(rz::config::keys::TLS_KEY, key_path.to_str().expect("utf-8"));
    let cfg = f(rz::config::RendezvousConfig::load(&env).expect("test config"));
    let tls = tokio_rustls::TlsAcceptor::from(
        rz::tls::server_config(&cfg.tls_key_path).expect("a usable server key"),
    );

    let metrics = svc::metrics::Metrics::new();
    let shared = Arc::new(rz::server::Shared {
        router: tokio::sync::Mutex::new(rz::ingress::Router {
            attachments: rz::attach::AttachRegistry::new(cfg.attach),
            mailboxes: rz::mailbox::MailboxStore::new(cfg.mailbox),
            labels: rz::label::Labeller::default(),
        }),
        limiter: tokio::sync::Mutex::new(rz::admission::SourceLimiter::new(cfg.admission)),
        bindings: tokio::sync::Mutex::new(Box::new(rz::binding::ChannelPinned::new(cfg.binding))),
        tls,
        connections: Arc::new(tokio::sync::Semaphore::new(cfg.max_connections)),
        config: cfg,
        metrics: metrics.clone(),
    });

    let listener = tokio::net::TcpListener::bind(SocketAddr::new(host, 0))
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    // A short grace: these tests hold client sockets open deliberately, and a
    // 120 s production grace would make every one of them a two-minute test.
    let shutdown = Arc::new(svc::shutdown::Shutdown::new(
        svc::shutdown::ShutdownConfig {
            grace: std::time::Duration::from_millis(500),
            drain_deadline: std::time::Duration::from_millis(200),
            teardown_step_timeout: std::time::Duration::from_millis(200),
        },
        metrics,
    ));
    let handle = shutdown.handle();
    let task = tokio::spawn(rz::server::serve(listener, Arc::clone(&shared), handle));

    Harness {
        addr,
        shared,
        server_spki: server_key.spki.clone(),
        shutdown,
        task,
    }
}

impl Harness {
    /// Drains and stops, returning the shutdown report.
    pub async fn stop(self) -> svc::shutdown::ShutdownReport {
        let report = self.shutdown.shutdown().await;
        let _ = self.task.await;
        report
    }
}

/// A framed client connection over an authenticated TLS 1.3 channel.
pub struct Client {
    stream: tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
}

impl Harness {
    /// Connects with a fresh device identity.
    pub async fn client(&self) -> Client {
        Client::connect_as(self.addr, &TestKey::generate(), &self.server_spki).await
    }

    /// Connects with a specific device identity, so a test can reuse or
    /// deliberately vary the authenticated key.
    pub async fn client_as(&self, key: &TestKey) -> Client {
        Client::connect_as(self.addr, key, &self.server_spki).await
    }

    /// Attempts a handshake presenting **no** client key.
    pub async fn anonymous_handshake(&self) -> Result<(), std::io::Error> {
        let tcp = tokio::net::TcpStream::connect(self.addr).await?;
        let connector =
            tokio_rustls::TlsConnector::from(TestKey::anonymous_client_config(&self.server_spki));
        connector
            .connect(keys::server_name(), tcp)
            .await
            .map(|_| ())
    }
}

impl Client {
    /// Connects, completing the mutual raw-public-key handshake.
    pub async fn connect_as(addr: SocketAddr, key: &TestKey, server_spki: &[u8]) -> Self {
        let tcp = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let connector = tokio_rustls::TlsConnector::from(key.client_config(server_spki));
        let stream = connector
            .connect(keys::server_name(), tcp)
            .await
            .expect("the mutual raw-public-key handshake completes");
        Self { stream }
    }

    /// Writes raw bytes, whatever they are.
    pub async fn write(&mut self, bytes: &[u8]) {
        use tokio::io::AsyncWriteExt as _;
        let _ = self.stream.write_all(bytes).await;
    }

    /// Reads one frame, or `None` if the peer closed first.
    pub async fn read_frame(&mut self) -> Option<(u8, Vec<u8>)> {
        use tokio::io::AsyncReadExt as _;
        let mut header = [0u8; rz::frame::HEADER_LEN];
        self.stream.read_exact(&mut header).await.ok()?;
        assert_eq!(header[0..4], rz::frame::MAGIC);
        let opcode = header[5];
        let len = usize::from(u16::from_be_bytes([header[6], header[7]]));
        let mut body = vec![0u8; len];
        self.stream.read_exact(&mut body).await.ok()?;
        Some((opcode, body))
    }

    /// Reads frames until one with `opcode` arrives, skipping the unsolicited
    /// `REFLEXIVE` this service sends on connect.
    pub async fn read_until(&mut self, opcode: rz::frame::Opcode) -> Option<Vec<u8>> {
        loop {
            let (op, body) = self.read_frame().await?;
            if op == opcode.as_wire() {
                return Some(body);
            }
        }
    }
}

/// Decodes an `ErrorEnvelope` body into its reason code, or `None` for the empty
/// success body.
pub fn reason_code(body: &[u8]) -> Option<String> {
    use prost::Message as _;
    if body.is_empty() {
        return None;
    }
    let env = twinvpn_schema::v1::ErrorEnvelope::decode(body).expect("an ErrorEnvelope");
    Some(env.reason_code)
}

/// Times out rather than hanging a test run for ever.
pub async fn within<T>(f: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(std::time::Duration::from_secs(5), f)
        .await
        .expect("the service answered within 5 s")
}
