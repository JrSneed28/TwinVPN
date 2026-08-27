//! A real presence aggregator, on a real socket.

#![allow(dead_code)]

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use twinvpn_presence as pr;
use twinvpn_service_common as svc;
// The shared TLS test kit — this was `tests/common/keys.rs` in both this
// service and `rendezvous` (RZ-8).
pub use svc::tls::testkit::{server_name, TestKey};

/// A running service and the address it is listening on.
pub struct Harness {
    /// Where to connect.
    pub addr: SocketAddr,
    /// The shared state, so a test can assert on the table directly.
    pub shared: Arc<pr::server::Shared>,
    /// The server's raw public key, for a client to pin.
    pub server_spki: Vec<u8>,
    shutdown: Arc<svc::shutdown::Shutdown>,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
}

/// Starts a presence aggregator bound to `host:0`.
pub async fn start(host: IpAddr) -> Harness {
    start_with(host, |c| c).await
}

/// Starts one with the configuration adjusted by `f`.
pub async fn start_with(
    host: IpAddr,
    f: impl FnOnce(pr::config::PresenceConfig) -> pr::config::PresenceConfig,
) -> Harness {
    // A fresh server identity per harness, so no key is ever checked in and two
    // concurrent tests cannot share one.
    let server_key = TestKey::generate();
    let key_path = server_key.write_pem(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        &format!(
            "pr-server-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ),
    );
    let env = svc::config::MapEnv::new()
        .with(pr::config::keys::TLS_CERT, "Cargo.toml")
        .with(pr::config::keys::TLS_KEY, key_path.to_str().expect("utf-8"));
    let mut cfg = pr::config::PresenceConfig::load(&env).expect("test config");
    cfg.frame_read_timeout = std::time::Duration::from_millis(300);
    let cfg = f(cfg);

    let metrics = svc::metrics::Metrics::new();
    let shared = Arc::new(pr::server::Shared::new(cfg, metrics.clone()).expect("a usable key"));

    let listener = tokio::net::TcpListener::bind(SocketAddr::new(host, 0))
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    let shutdown = Arc::new(svc::shutdown::Shutdown::new(
        svc::shutdown::ShutdownConfig {
            grace: std::time::Duration::from_millis(500),
            drain_deadline: std::time::Duration::from_millis(200),
            teardown_step_timeout: std::time::Duration::from_millis(200),
        },
        metrics,
    ));
    let handle = shutdown.handle();
    let task = tokio::spawn(pr::server::serve(listener, Arc::clone(&shared), handle));

    Harness {
        addr,
        shared,
        server_spki: server_key.spki.clone(),
        shutdown,
        task,
    }
}

impl Harness {
    /// Drains and stops.
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

    /// Connects with a specific device identity.
    pub async fn client_as(&self, key: &TestKey) -> Client {
        Client::connect_as(self.addr, key, &self.server_spki).await
    }

    /// Attempts a handshake presenting **no** client key.
    pub async fn anonymous_handshake(&self) -> Result<(), std::io::Error> {
        let tcp = tokio::net::TcpStream::connect(self.addr).await?;
        let connector =
            tokio_rustls::TlsConnector::from(TestKey::anonymous_client_config(&self.server_spki));
        connector.connect(server_name(), tcp).await.map(|_| ())
    }
}

impl Client {
    /// Connects, completing the mutual raw-public-key handshake.
    pub async fn connect_as(addr: SocketAddr, key: &TestKey, server_spki: &[u8]) -> Self {
        let tcp = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let connector = tokio_rustls::TlsConnector::from(key.client_config(server_spki));
        let stream = connector
            .connect(server_name(), tcp)
            .await
            .expect("the mutual raw-public-key handshake completes");
        Self { stream }
    }

    /// Writes raw bytes.
    pub async fn write(&mut self, bytes: &[u8]) {
        use tokio::io::AsyncWriteExt as _;
        let _ = self.stream.write_all(bytes).await;
    }

    /// Reads one frame, or `None` if the peer closed first.
    pub async fn read_frame(&mut self) -> Option<(u8, Vec<u8>)> {
        use tokio::io::AsyncReadExt as _;
        let mut header = [0u8; pr::frame::HEADER_LEN];
        self.stream.read_exact(&mut header).await.ok()?;
        assert_eq!(header[0..4], pr::frame::MAGIC);
        let opcode = header[5];
        let len = u32::from_be_bytes([header[6], header[7], header[8], header[9]]) as usize;
        let mut body = vec![0u8; len];
        self.stream.read_exact(&mut body).await.ok()?;
        Some((opcode, body))
    }

    /// Reads frames until one with `opcode` arrives.
    pub async fn read_until(&mut self, opcode: pr::frame::Opcode) -> Option<Vec<u8>> {
        loop {
            let (op, body) = self.read_frame().await?;
            if op == opcode.as_wire() {
                return Some(body);
            }
        }
    }

    /// Binds this connection to `device_id` and waits for the ack.
    pub async fn bind(&mut self, device_id: [u8; 32]) {
        self.write(&pr::frame::encode(pr::frame::Opcode::Bind, &device_id))
            .await;
        within(self.read_until(pr::frame::Opcode::Ack))
            .await
            .expect("bind acked");
    }
}

/// Decodes a `PublishPresenceResponse`.
#[must_use]
pub fn response(body: &[u8]) -> twinvpn_schema::v1::PublishPresenceResponse {
    use prost::Message as _;
    twinvpn_schema::v1::PublishPresenceResponse::decode(body).expect("a response")
}

/// Times out rather than hanging a test run for ever.
pub async fn within<T>(f: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(std::time::Duration::from_secs(5), f)
        .await
        .expect("the service answered within 5 s")
}
