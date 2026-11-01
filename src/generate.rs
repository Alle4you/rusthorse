//! Generating secret values from the operating system's random number
//! generator, so that a new credential can be created without anybody —
//! human or AI — ever typing or seeing it.

use serde::{Deserialize, Serialize};

use crate::protocol::SecretString;

/// The characters a generated value is drawn from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Alphabet {
    /// `A–Z a–z 0–9` (62 characters, about 5.95 bits each).
    Alnum,
    /// Letters, digits and `-_.:@+=~%^` — symbols that need no quoting in
    /// URLs or most configuration files (72 characters, about 6.17 bits each).
    Symbols,
    /// `0–9 a–f` (4 bits each), for systems that want hexadecimal keys.
    Hex,
}

impl Alphabet {
    /// The characters of this alphabet.
    pub fn chars(self) -> &'static [u8] {
        const ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        const SYMBOLS: &[u8] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.:@+=~%^";
        const HEX: &[u8] = b"0123456789abcdef";
        match self {
            Alphabet::Alnum => ALNUM,
            Alphabet::Symbols => SYMBOLS,
            Alphabet::Hex => HEX,
        }
    }
}

/// What to generate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Spec {
    /// Number of characters (8–1024).
    pub length: u16,
    /// Characters to draw from.
    pub alphabet: Alphabet,
}

impl Default for Spec {
    /// 32 alphanumeric characters: about 190 bits.
    fn default() -> Self {
        Self {
            length: 32,
            alphabet: Alphabet::Alnum,
        }
    }
}

impl Spec {
    /// Shortest and longest accepted lengths.
    pub const LENGTHS: std::ops::RangeInclusive<u16> = 8..=1024;

    /// Bits of entropy of a value generated with this spec.
    pub fn entropy_bits(self) -> f64 {
        f64::from(self.length) * (self.alphabet.chars().len() as f64).log2()
    }
}

/// Errors from [`generate`].
#[derive(Debug, thiserror::Error)]
pub enum GenerateError {
    /// The length is out of range.
    #[error("the length must be between 8 and 1024")]
    Length,
    /// The operating system could not provide random bytes.
    #[error("cannot get random bytes from the operating system: {0}")]
    Random(getrandom::Error),
}

/// Generate a value: each character is drawn uniformly (rejection sampling,
/// so no character is more likely than another).
pub fn generate(spec: Spec) -> Result<SecretString, GenerateError> {
    if !Spec::LENGTHS.contains(&spec.length) {
        return Err(GenerateError::Length);
    }
    let chars = spec.alphabet.chars();
    let n = chars.len() as u32;
    // Largest multiple of `n` that fits in a u32; draws at or above it are
    // rejected so that `draw % n` is uniform.
    let limit = u32::MAX - (u32::MAX % n);
    let mut value = SecretString::new(String::with_capacity(spec.length as usize));
    while value.len() < spec.length as usize {
        let draw = getrandom::u32().map_err(GenerateError::Random)?;
        if draw < limit {
            value.push(chars[(draw % n) as usize] as char);
        }
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_have_the_requested_shape() {
        for alphabet in [Alphabet::Alnum, Alphabet::Symbols, Alphabet::Hex] {
            let spec = Spec {
                length: 40,
                alphabet,
            };
            let value = generate(spec).expect("generate");
            assert_eq!(value.len(), 40);
            assert!(
                value.bytes().all(|b| alphabet.chars().contains(&b)),
                "{alphabet:?}"
            );
        }
        assert!(
            generate(Spec {
                length: 4,
                alphabet: Alphabet::Alnum
            })
            .is_err()
        );
    }

    #[test]
    fn values_differ_and_cover_the_alphabet() {
        let a = generate(Spec::default()).expect("a");
        let b = generate(Spec::default()).expect("b");
        assert_ne!(*a, *b);
        // 1024 hex characters (64 of each expected): every digit appears and
        // none is wildly more frequent than the others.
        let big = generate(Spec {
            length: 1024,
            alphabet: Alphabet::Hex,
        })
        .expect("big");
        let mut counts = [0usize; 16];
        for c in big.bytes() {
            counts[(c as char).to_digit(16).expect("hex") as usize] += 1;
        }
        assert!(counts.iter().all(|&c| c > 20 && c < 120), "{counts:?}");
    }

    #[test]
    fn entropy_is_reported() {
        assert!((Spec::default().entropy_bits() - 190.5).abs() < 1.0);
    }
}
