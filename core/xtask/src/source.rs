//! A Rust source scanner that ignores comments and string literals.
//!
//! # Why this is not a `grep`
//!
//! Both source lints here look for *code*. A `grep` would fire on this very
//! file — which names every deny-listed API in its own tables — and on every
//! doc comment in `twinvpn-env` that explains *why* `Instant::now` is banned. A
//! lint that fires on its own documentation is one somebody will disable.
//!
//! So the scanner blanks comments and literals **in place**, replacing each
//! byte with a space, and the caller matches against the blanked copy. Byte
//! offsets and line numbers are preserved exactly, so a violation still reports
//! the line it is on.
//!
//! It is not a Rust parser and does not need to be: over-blanking would hide a
//! violation, so the rules below are conservative in the other direction — an
//! unterminated literal blanks to end of file, and a lifetime is never mistaken
//! for a character literal.

/// Replaces every comment and literal byte with a space, preserving length.
#[must_use]
pub fn blank_comments_and_literals(src: &str) -> String {
    let bytes = src.as_bytes();
    let mut out: Vec<u8> = bytes.to_vec();
    let mut i = 0usize;

    while i < bytes.len() {
        match bytes[i] {
            b'/' if i + 1 < bytes.len() && bytes[i + 1] == b'/' => {
                while i < bytes.len() && bytes[i] != b'\n' {
                    out[i] = b' ';
                    i += 1;
                }
            }
            b'/' if i + 1 < bytes.len() && bytes[i + 1] == b'*' => {
                let mut depth = 1usize;
                out[i] = b' ';
                out[i + 1] = b' ';
                i += 2;
                while i < bytes.len() && depth > 0 {
                    if i + 1 < bytes.len() && bytes[i] == b'/' && bytes[i + 1] == b'*' {
                        depth += 1;
                        out[i] = b' ';
                        out[i + 1] = b' ';
                        i += 2;
                    } else if i + 1 < bytes.len() && bytes[i] == b'*' && bytes[i + 1] == b'/' {
                        depth -= 1;
                        out[i] = b' ';
                        out[i + 1] = b' ';
                        i += 2;
                    } else {
                        if bytes[i] != b'\n' {
                            out[i] = b' ';
                        }
                        i += 1;
                    }
                }
            }
            b'r' | b'b' if raw_string_start(bytes, i).is_some() => {
                // `is_some()` in the guard, destructured here: the `else` arm is
                // unreachable, and writing it out rather than `expect`ing keeps
                // this function panic-free by construction.
                let Some((hashes, body_start)) = raw_string_start(bytes, i) else {
                    i += 1;
                    continue;
                };
                for slot in out.iter_mut().take(body_start).skip(i) {
                    *slot = b' ';
                }
                i = body_start;
                // Scan for the closing `"` followed by `hashes` `#`.
                loop {
                    if i >= bytes.len() {
                        break;
                    }
                    if bytes[i] == b'"' && closing_hashes(bytes, i + 1) >= hashes {
                        for slot in out.iter_mut().take(i + 1 + hashes).skip(i) {
                            *slot = b' ';
                        }
                        i += 1 + hashes;
                        break;
                    }
                    if bytes[i] != b'\n' {
                        out[i] = b' ';
                    }
                    i += 1;
                }
            }
            b'"' => {
                out[i] = b' ';
                i += 1;
                while i < bytes.len() {
                    if bytes[i] == b'\\' {
                        out[i] = b' ';
                        if i + 1 < bytes.len() {
                            out[i + 1] = b' ';
                        }
                        i += 2;
                        continue;
                    }
                    if bytes[i] == b'"' {
                        out[i] = b' ';
                        i += 1;
                        break;
                    }
                    if bytes[i] != b'\n' {
                        out[i] = b' ';
                    }
                    i += 1;
                }
            }
            b'\'' if char_literal_len(bytes, i).is_some() => {
                let Some(len) = char_literal_len(bytes, i) else {
                    i += 1;
                    continue;
                };
                for slot in out.iter_mut().take(i + len).skip(i) {
                    *slot = b' ';
                }
                i += len;
            }
            _ => i += 1,
        }
    }

    String::from_utf8_lossy(&out).into_owned()
}

/// If a raw string starts at `i`, returns `(hash count, offset of the body)`.
fn raw_string_start(bytes: &[u8], i: usize) -> Option<(usize, usize)> {
    let mut j = i;
    if bytes.get(j) == Some(&b'b') {
        j += 1;
    }
    if bytes.get(j) != Some(&b'r') {
        return None;
    }
    j += 1;
    let hashes_start = j;
    while bytes.get(j) == Some(&b'#') {
        j += 1;
    }
    if bytes.get(j) != Some(&b'"') {
        return None;
    }
    Some((j - hashes_start, j + 1))
}

fn closing_hashes(bytes: &[u8], mut i: usize) -> usize {
    let start = i;
    while bytes.get(i) == Some(&b'#') {
        i += 1;
    }
    i - start
}

/// If a character literal starts at `i`, returns its total length.
///
/// Returns `None` for a lifetime (`'a`, `'static`), which shares the opening
/// quote and must not be blanked — blanking `'a` in `fn f<'a>(x: &'a str)` would
/// swallow the code after it.
fn char_literal_len(bytes: &[u8], i: usize) -> Option<usize> {
    if bytes.get(i) != Some(&b'\'') {
        return None;
    }
    // `'\x'` — an escape is always a character literal.
    if bytes.get(i + 1) == Some(&b'\\') {
        let mut j = i + 2;
        while j < bytes.len() && j < i + 12 {
            if bytes[j] == b'\'' {
                return Some(j - i + 1);
            }
            j += 1;
        }
        return None;
    }
    // `'x'` — one character then a closing quote.
    let mut j = i + 1;
    // Step over one UTF-8 scalar.
    if j >= bytes.len() {
        return None;
    }
    j += 1;
    while j < bytes.len() && (bytes[j] & 0xc0) == 0x80 {
        j += 1;
    }
    if bytes.get(j) == Some(&b'\'') {
        return Some(j - i + 1);
    }
    None
}

/// A source file's path and its blanked contents.
pub struct ScannedFile {
    /// The path, relative to the workspace root.
    pub path: String,
    /// The original contents, for line extraction.
    pub original: String,
    /// The contents with comments and literals blanked.
    pub blanked: String,
}

impl ScannedFile {
    /// Scans one file's contents.
    #[must_use]
    pub fn new(path: impl Into<String>, contents: &str) -> Self {
        Self {
            path: path.into(),
            blanked: blank_comments_and_literals(contents),
            original: contents.to_owned(),
        }
    }

    /// The 1-based line number containing byte offset `at`.
    #[must_use]
    pub fn line_of(&self, at: usize) -> usize {
        self.original[..at.min(self.original.len())]
            .bytes()
            .filter(|b| *b == b'\n')
            .count()
            + 1
    }

    /// The text of the line containing byte offset `at`, trimmed.
    #[must_use]
    pub fn line_text(&self, at: usize) -> String {
        let at = at.min(self.original.len());
        let start = self.original[..at].rfind('\n').map_or(0, |p| p + 1);
        let end = self.original[at..]
            .find('\n')
            .map_or(self.original.len(), |p| at + p);
        self.original[start..end].trim().to_owned()
    }
}
