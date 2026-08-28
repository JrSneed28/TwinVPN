//! The relay's randomness source.
//!
//! **Authority:** ADR-0018 CD-2 (every component takes its `Env` at
//! construction — no global, no ambient default), CD-3 (the ban on ambient
//! randomness inside `/core`), ADR-0005 §11.1(2) (the leg handshake needs a
//! fresh ephemeral per handshake).
//!
//! # Why this is here rather than borrowed
//!
//! `twinvpn-crypto`'s relay-leg handshake takes an injected
//! [`twinvpn_crypto::relay_leg::Entropy`] rather than reaching for a CSPRNG
//! itself. Somebody has to supply one, and in `/core` that somebody is the
//! shell — `twinvpn_platform_linux::SystemEntropy`. The server artifacts do not
//! link the core (ADR-0018 §11.2 rows 2.8/2.11) and have no shell, so this
//! module is the relay's equivalent, written the same way and reading the same
//! file so the two cannot disagree about what "the platform CSPRNG" means.
//!
//! # `/dev/urandom`, and why that is the right file
//!
//! It is the interface `twinvpn_platform_linux::SystemEntropy` already uses. On
//! any kernel this service can run on, `/dev/urandom` is the seeded CSPRNG and
//! never blocks; `getrandom(2)` would be the same generator through a syscall
//! this crate cannot make without `unsafe` (DP-4) or a new dependency (DP-8).
//!
//! **The handle is opened once, at construction.** A per-call `open` would make
//! every handshake depend on `/dev` still being mounted and on a file descriptor
//! being available under load — two failure modes that arrive exactly when a
//! relay is busiest.
//!
//! # A failure is fatal to the handshake, never papered over
//!
//! [`SystemEntropy::fill`] returns `Err` and the caller refuses the leg. There is
//! no fallback generator, because a fallback CSPRNG is indistinguishable from a
//! working one right up until it matters — the same rule `twinvpn-crypto` states
//! at its own `Random` binding. A relay that cannot get randomness admits nothing,
//! which is the fail-closed direction, and [`SystemEntropy::probe`] makes that
//! visible at startup rather than at the first handshake.

use std::io::Read;
use std::sync::Mutex;

use twinvpn_crypto::relay_leg::Entropy;

/// The platform CSPRNG.
pub struct SystemEntropy {
    /// Opened once. Behind a `Mutex` because `Read::read_exact` needs `&mut` and
    /// the trait offers `&self`; the critical section is one `read` of at most a
    /// few dozen bytes and is never held across an `.await`.
    file: Mutex<std::fs::File>,
}

impl SystemEntropy {
    /// Where the randomness comes from. The same path
    /// `twinvpn_platform_linux::SystemEntropy` uses.
    pub const SOURCE: &'static str = "/dev/urandom";

    /// Opens the CSPRNG.
    ///
    /// # Errors
    ///
    /// [`std::io::Error`] if the source cannot be opened. A relay that cannot
    /// open it must refuse to start: it could establish no leg, and it would
    /// discover that one dropped handshake at a time.
    pub fn open() -> std::io::Result<Self> {
        Ok(Self {
            file: Mutex::new(std::fs::File::open(Self::SOURCE)?),
        })
    }

    /// Draws 32 bytes to prove the source works.
    ///
    /// # Errors
    ///
    /// [`std::io::Error`].
    pub fn probe(&self) -> std::io::Result<()> {
        let mut probe = [0_u8; 32];
        self.fill(&mut probe)
            .map_err(|_| std::io::Error::other("entropy source returned no bytes"))
    }
}

impl std::fmt::Debug for SystemEntropy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // No state worth printing, and nothing that could ever be drawn from it.
        f.debug_struct("SystemEntropy")
            .field("source", &Self::SOURCE)
            .finish()
    }
}

impl Entropy for SystemEntropy {
    fn fill(&self, dst: &mut [u8]) -> Result<(), twinvpn_crypto::relay_leg::EntropyError> {
        if dst.is_empty() {
            return Ok(());
        }
        let mut file = self
            .file
            .lock()
            .map_err(|_| twinvpn_crypto::relay_leg::EntropyError::EntropyUnavailable)?;
        file.read_exact(dst)
            .map_err(|_| twinvpn_crypto::relay_leg::EntropyError::EntropyUnavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn the_source_yields_bytes_and_does_not_repeat_them() {
        let e = SystemEntropy::open().expect("/dev/urandom opens");
        e.probe().expect("probe");
        let mut a = [0_u8; 32];
        let mut b = [0_u8; 32];
        e.fill(&mut a).expect("fill");
        e.fill(&mut b).expect("fill");
        assert_ne!(a, b, "two draws from a CSPRNG must not be equal");
        assert_ne!(a, [0_u8; 32], "an all-zero draw is a broken source");
    }

    #[test]
    fn a_zero_length_fill_is_not_an_error() {
        let e = SystemEntropy::open().expect("opens");
        assert!(e.fill(&mut []).is_ok());
    }

    #[test]
    fn it_is_usable_as_the_injected_source_the_handshake_takes() {
        // The whole point of the module: it satisfies the trait
        // `twinvpn-crypto`'s relay leg asks for.
        let e: Arc<dyn Entropy> = Arc::new(SystemEntropy::open().expect("opens"));
        let mut out = [0_u8; 8];
        e.fill(&mut out).expect("fill through the trait object");
    }

    #[test]
    fn it_renders_nothing_that_was_drawn() {
        let e = SystemEntropy::open().expect("opens");
        let rendered = format!("{e:?}");
        assert!(rendered.contains("/dev/urandom"));
        assert!(!rendered.contains("file"));
    }
}
