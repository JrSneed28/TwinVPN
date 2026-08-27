//! A real TLS listener over a minimal claim protocol, so the authentication
//! assertions are about wire behaviour rather than about a config struct.
//!
//! The protocol is the smallest thing that can express the attack. A peer opens
//! a connection, presents its RFC 7250 key, and sends one or more
//! `MAGIC || subject[32]` frames on that **long-lived** connection; the server
//! binds each claimed subject to the authenticated channel identity and answers
//! `status || len || code`. That is the rendezvous' `ATTACH` and presence's
//! `BIND` with everything service-specific removed.
//!
//! # Why the connection is long-lived
//!
//! Because the invariant is. `ChannelPinned` scopes the "one channel speaks for
//! one subject" half to channels with a **live holder**: a key that disconnects
//! and later claims a different, unheld subject has gained nothing an entirely
//! fresh key would not have. A harness that opened a new connection per claim
//! would silently never exercise that half — it would pass against a binding
//! table that did not implement it at all.

#![allow(dead_code)]

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::sync::Mutex;

use twinvpn_service_common::binding::{Binding, ChannelPinned, Claim};
use twinvpn_service_common::tls::testkit::TestKey;
use twinvpn_service_common::tls::{self, ServerTlsBuilder};

/// The claim frame's magic, so a plaintext answer is distinguishable from a TLS
/// alert by inspection.
pub const MAGIC: [u8; 4] = *b"TVSC";

/// The subject width, matching `limits.json identifiers.device_id_bytes`.
pub const SUBJECT_LEN: usize = 32;

/// How long a peer has to complete a handshake before it is dropped.
pub const HANDSHAKE_DEADLINE: Duration = Duration::from_millis(400);

/// What the server answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    /// The claim was accepted.
    Accepted,
    /// The claim was refused, with this registered reason code.
    Refused(String),
    /// The peer was not answered at all.
    Silence,
}

impl Answer {
    /// A refusal carrying `code`.
    #[must_use]
    pub fn refused(code: &str) -> Self {
        Self::Refused(code.to_owned())
    }
}

/// A claim frame.
#[must_use]
pub fn claim_frame(subject: [u8; SUBJECT_LEN]) -> Vec<u8> {
    let mut v = MAGIC.to_vec();
    v.extend_from_slice(&subject);
    v
}

/// The server name a test client asks for.
#[must_use]
pub fn server_name() -> rustls::pki_types::ServerName<'static> {
    tls::testkit::server_name()
}

/// Bounds a future, so a hung assertion fails rather than hangs CI.
pub async fn within<F: std::future::Future>(f: F) -> Option<F::Output> {
    tokio::time::timeout(Duration::from_secs(3), f).await.ok()
}

/// An open, authenticated connection.
///
/// Dropping it closes the connection, which is what makes the
/// binding-outlives-the-connection assertion meaningful.
pub struct Session {
    tls: tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
}

impl Session {
    /// Sends one claim and reads the answer.
    pub async fn claim(&mut self, subject: [u8; SUBJECT_LEN]) -> Answer {
        if self.tls.write_all(&claim_frame(subject)).await.is_err()
            || self.tls.flush().await.is_err()
        {
            return Answer::Silence;
        }
        self.read_answer().await
    }

    /// Sends arbitrary bytes and reads whatever comes back.
    pub async fn send_raw(&mut self, body: &[u8]) -> Answer {
        if self.tls.write_all(body).await.is_err() || self.tls.flush().await.is_err() {
            return Answer::Silence;
        }
        self.read_answer().await
    }

    async fn read_answer(&mut self) -> Answer {
        let mut head = [0u8; 2];
        let read =
            tokio::time::timeout(Duration::from_millis(800), self.tls.read_exact(&mut head)).await;
        if !matches!(read, Ok(Ok(_))) {
            return Answer::Silence;
        }
        if head[0] == 0 {
            return Answer::Accepted;
        }
        let mut code = vec![0u8; head[1] as usize];
        let read =
            tokio::time::timeout(Duration::from_millis(800), self.tls.read_exact(&mut code)).await;
        if !matches!(read, Ok(Ok(_))) {
            return Answer::Silence;
        }
        Answer::Refused(String::from_utf8_lossy(&code).into_owned())
    }
}

/// A running listener.
pub struct Harness {
    /// Where to connect.
    pub addr: SocketAddr,
    /// The SPKI a client pins.
    pub server_spki: Vec<u8>,
    accepted: Arc<AtomicUsize>,
    refused_handshakes: Arc<AtomicUsize>,
    stop: tokio::sync::watch::Sender<bool>,
    joined: tokio::task::JoinHandle<()>,
}

impl Harness {
    /// How many claims the binding table accepted.
    #[must_use]
    pub fn accepted_claims(&self) -> usize {
        self.accepted.load(Ordering::SeqCst)
    }

    /// How many handshakes did not complete.
    #[must_use]
    pub fn handshakes_refused(&self) -> usize {
        self.refused_handshakes.load(Ordering::SeqCst)
    }

    /// Opens an authenticated session as `key`.
    pub async fn connect_as(&self, key: &TestKey) -> Option<Session> {
        let tcp = tokio::net::TcpStream::connect(self.addr).await.ok()?;
        let connector = tokio_rustls::TlsConnector::from(key.client_config(&self.server_spki));
        let tls = within(connector.connect(server_name(), tcp)).await?.ok()?;
        Some(Session { tls })
    }

    /// Opens a session as `key`, makes one claim, and closes it.
    pub async fn claim_once(&self, key: &TestKey, subject: [u8; SUBJECT_LEN]) -> Answer {
        match self.connect_as(key).await {
            None => Answer::Silence,
            Some(mut s) => {
                let a = s.claim(subject).await;
                drop(s);
                // Let the server observe the close and release the holder.
                tokio::time::sleep(Duration::from_millis(80)).await;
                a
            }
        }
    }

    /// Attempts a handshake presenting **no** client key.
    ///
    /// # Errors
    ///
    /// Always, if `client_auth_mandatory` holds.
    pub async fn anonymous_handshake(&self) -> Result<(), String> {
        let tcp = tokio::net::TcpStream::connect(self.addr)
            .await
            .map_err(|e| e.to_string())?;
        let connector =
            tokio_rustls::TlsConnector::from(TestKey::anonymous_client_config(&self.server_spki));
        match within(connector.connect(server_name(), tcp)).await {
            None => Err("timed out".to_owned()),
            Some(Err(e)) => Err(e.to_string()),
            Some(Ok(mut s)) => {
                // rustls may defer the alert until the first write.
                s.write_all(&claim_frame([9u8; SUBJECT_LEN]))
                    .await
                    .map_err(|e| e.to_string())?;
                s.flush().await.map_err(|e| e.to_string())?;
                let mut buf = Vec::new();
                match tokio::time::timeout(Duration::from_millis(800), s.read_to_end(&mut buf))
                    .await
                {
                    Ok(Ok(_)) if buf.is_empty() => Err("no answer".to_owned()),
                    Ok(Err(e)) => Err(e.to_string()),
                    _ => Ok(()),
                }
            }
        }
    }

    /// Stops the listener.
    pub async fn stop(self) {
        let _ = self.stop.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(2), self.joined).await;
    }
}

/// Starts a listener on `ip`, on an ephemeral port.
pub async fn start(ip: IpAddr) -> Harness {
    let key = TestKey::generate();
    let built = ServerTlsBuilder::from_pkcs8_der(key.pkcs8().to_vec())
        .build()
        .expect("a usable key");
    let server_spki = built.public_key().to_vec();
    let acceptor = tokio_rustls::TlsAcceptor::from(built.config());

    let listener = tokio::net::TcpListener::bind(SocketAddr::new(ip, 0))
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");

    let accepted = Arc::new(AtomicUsize::new(0));
    let refused_handshakes = Arc::new(AtomicUsize::new(0));
    let bindings: Arc<Mutex<ChannelPinned<[u8; SUBJECT_LEN]>>> =
        Arc::new(Mutex::new(ChannelPinned::default()));

    let (stop, mut stop_rx) = tokio::sync::watch::channel(false);

    let joined = {
        let accepted = accepted.clone();
        let refused_handshakes = refused_handshakes.clone();
        tokio::spawn(async move {
            loop {
                let stream = tokio::select! {
                    _ = stop_rx.changed() => break,
                    r = listener.accept() => match r {
                        Ok((s, _)) => s,
                        Err(_) => continue,
                    },
                };
                let acceptor = acceptor.clone();
                let bindings = bindings.clone();
                let accepted = accepted.clone();
                let refused_handshakes = refused_handshakes.clone();
                tokio::spawn(async move {
                    serve_one(stream, acceptor, bindings, accepted, refused_handshakes).await;
                });
            }
        })
    };

    Harness {
        addr,
        server_spki,
        accepted,
        refused_handshakes,
        stop,
        joined,
    }
}

async fn serve_one(
    stream: tokio::net::TcpStream,
    acceptor: tokio_rustls::TlsAcceptor,
    bindings: Arc<Mutex<ChannelPinned<[u8; SUBJECT_LEN]>>>,
    accepted: Arc<AtomicUsize>,
    refused_handshakes: Arc<AtomicUsize>,
) {
    let _ = stream.set_nodelay(true);
    // The handshake takes the same stall deadline a partial frame does.
    let Ok((mut tls, channel)) =
        tls::accept_with_deadline(&acceptor, stream, HANDSHAKE_DEADLINE).await
    else {
        refused_handshakes.fetch_add(1, Ordering::SeqCst);
        return;
    };

    // What this connection actually acquired, so teardown releases that and only
    // that.
    let mut held: Option<[u8; SUBJECT_LEN]> = None;

    loop {
        let mut frame = [0u8; MAGIC.len() + SUBJECT_LEN];
        let read = tokio::time::timeout(Duration::from_secs(5), tls.read_exact(&mut frame)).await;
        // A malformed, short or absent frame is not answered at all: an
        // authenticated peer is still not a trusted one.
        if !matches!(read, Ok(Ok(_))) || frame[..MAGIC.len()] != MAGIC {
            break;
        }
        let mut subject = [0u8; SUBJECT_LEN];
        subject.copy_from_slice(&frame[MAGIC.len()..]);

        let outcome = {
            let mut b = bindings.lock().await;
            b.claim(&channel, subject, Instant::now())
        };
        match outcome {
            Claim::Accepted => {
                accepted.fetch_add(1, Ordering::SeqCst);
                held = Some(subject);
                let _ = tls.write_all(&[0u8, 0u8]).await;
                let _ = tls.flush().await;
            }
            Claim::Refused(r) => {
                let code = r.reason_code().as_str().as_bytes();
                let mut answer = vec![1u8, u8::try_from(code.len()).expect("short code")];
                answer.extend_from_slice(code);
                let _ = tls.write_all(&answer).await;
                let _ = tls.flush().await;
                // A refused peer's connection is closed, as the rendezvous does:
                // it has nothing further to say on a channel it is not entitled
                // to.
                break;
            }
        }
    }

    let _ = tls.shutdown().await;
    // Release exactly what this connection took, and nothing if it took
    // nothing. The binding OUTLIVES the connection: release only decrements the
    // holder count and refreshes the TTL.
    if let Some(held) = held {
        bindings
            .lock()
            .await
            .release(&channel, &held, Instant::now());
    }
}
