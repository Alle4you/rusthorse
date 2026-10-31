//! Streaming redaction of secret values from command output.
//!
//! Output arrives in arbitrary chunks, so a secret can be split across two
//! reads. The [`Redactor`] holds back trailing bytes that could be the start of
//! a secret until the next chunk (or the end of the stream) decides.
//!
//! Redaction is exact-match only: a command that encodes, splits or
//! transforms a secret (base64, hex, `rev`, ...) defeats it. It protects
//! against *accidental* disclosure, not against a command written to leak.

use zeroize::Zeroizing;

/// Secrets shorter than this are not redacted (they would match everywhere).
pub const MIN_REDACT_LEN: usize = 4;

/// Replaces secret byte strings in a stream with `[REDACTED:<label>]`.
pub struct Redactor {
    /// (secret, replacement), longest secret first so the longest match wins.
    patterns: Vec<(Zeroizing<Vec<u8>>, Vec<u8>)>,
    pending: Zeroizing<Vec<u8>>,
}

impl Redactor {
    /// Build a redactor from `(label, secret)` pairs. Secrets shorter than
    /// [`MIN_REDACT_LEN`] bytes are ignored; see [`Redactor::too_short`].
    pub fn new<'a>(secrets: impl IntoIterator<Item = (&'a str, &'a [u8])>) -> Self {
        let mut patterns: Vec<(Zeroizing<Vec<u8>>, Vec<u8>)> = Vec::new();
        for (label, secret) in secrets {
            if secret.len() < MIN_REDACT_LEN || patterns.iter().any(|(p, _)| p.as_slice() == secret)
            {
                continue;
            }
            patterns.push((
                Zeroizing::new(secret.to_vec()),
                format!("[REDACTED:{label}]").into_bytes(),
            ));
        }
        patterns.sort_by_key(|p| std::cmp::Reverse(p.0.len()));
        Self {
            patterns,
            pending: Zeroizing::new(Vec::new()),
        }
    }

    /// Whether a secret is too short to be redacted.
    pub fn too_short(secret: &[u8]) -> bool {
        secret.len() < MIN_REDACT_LEN
    }

    /// Feed a chunk; returns the bytes that are safe to emit now.
    pub fn push(&mut self, data: &[u8]) -> Vec<u8> {
        self.pending.extend_from_slice(data);
        self.drain(false)
    }

    /// Signal the end of the stream; returns everything still held back.
    pub fn finish(&mut self) -> Vec<u8> {
        self.drain(true)
    }

    fn drain(&mut self, at_end: bool) -> Vec<u8> {
        let buf = std::mem::replace(&mut self.pending, Zeroizing::new(Vec::new()));
        let mut out = Vec::with_capacity(buf.len());
        let mut i = 0;
        'scan: while i < buf.len() {
            let rest = &buf[i..];
            for (secret, replacement) in &self.patterns {
                if rest.starts_with(secret) {
                    out.extend_from_slice(replacement);
                    i += secret.len();
                    continue 'scan;
                }
            }
            if !at_end
                && self
                    .patterns
                    .iter()
                    .any(|(secret, _)| rest.len() < secret.len() && secret.starts_with(rest))
            {
                // `rest` may be the beginning of a secret split across reads.
                break;
            }
            out.push(buf[i]);
            i += 1;
        }
        self.pending.extend_from_slice(&buf[i..]);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(secrets: &[(&str, &str)], chunks: &[&str]) -> String {
        let mut r = Redactor::new(secrets.iter().map(|(l, s)| (*l, s.as_bytes())));
        let mut out = Vec::new();
        for chunk in chunks {
            out.extend(r.push(chunk.as_bytes()));
        }
        out.extend(r.finish());
        String::from_utf8(out).expect("utf8")
    }

    #[test]
    fn replaces_whole_secret() {
        assert_eq!(
            run(&[("KEY", "sk-12345")], &["token=sk-12345 ok"]),
            "token=[REDACTED:KEY] ok"
        );
    }

    #[test]
    fn handles_secret_split_across_chunks() {
        assert_eq!(
            run(&[("KEY", "sk-12345")], &["a sk-1", "23", "45 b"]),
            "a [REDACTED:KEY] b"
        );
    }

    #[test]
    fn emits_partial_prefix_at_end() {
        assert_eq!(run(&[("KEY", "sk-12345")], &["tail sk-12"]), "tail sk-12");
    }

    #[test]
    fn does_not_hold_back_unrelated_bytes() {
        let mut r = Redactor::new([("KEY", b"secret-value".as_slice())]);
        assert_eq!(r.push(b"hello\n"), b"hello\n");
        assert_eq!(r.push(b"sec"), b"");
        assert_eq!(r.push(b"ond\n"), b"second\n");
    }

    #[test]
    fn longest_match_wins_and_multiple_secrets() {
        assert_eq!(
            run(&[("A", "abcd"), ("B", "abcdef")], &["x abcdef y abcd z"]),
            "x [REDACTED:B] y [REDACTED:A] z"
        );
    }

    #[test]
    fn short_secrets_are_ignored() {
        assert_eq!(run(&[("PIN", "123")], &["pin 123"]), "pin 123");
        assert!(Redactor::too_short(b"123"));
    }

    #[test]
    fn repeated_occurrences() {
        assert_eq!(
            run(&[("K", "zzzz")], &["zzzzzzzz", "zz"]),
            "[REDACTED:K][REDACTED:K]zz"
        );
    }
}
