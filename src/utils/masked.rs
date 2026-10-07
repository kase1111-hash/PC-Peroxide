//! String literals kept out of the executable in plain text.
//!
//! Detection rules contain the very strings they look for ("beacon.dll",
//! ransom-note phrases, miner pool URLs). Stored verbatim, those strings make
//! every copy of PC-Peroxide match its own rules. [`masked!`](crate::masked)
//! and [`masked_bytes!`](crate::masked_bytes) XOR a literal at compile time,
//! so only the masked bytes end up in the binary, and restore it at runtime.

const KEY: u8 = 0x5A;

/// Masks `text`; `N` must be its length in bytes.
#[doc(hidden)]
pub const fn mask<const N: usize>(text: &str) -> [u8; N] {
    let bytes = text.as_bytes();
    let mut out = [0u8; N];
    let mut i = 0;
    while i < N {
        out[i] = bytes[i] ^ KEY;
        i += 1;
    }
    out
}

/// Restores bytes produced by [`mask`].
#[doc(hidden)]
pub fn unmask(masked: &[u8]) -> Vec<u8> {
    masked.iter().map(|b| b ^ KEY).collect()
}

/// A `String` built from a literal that is stored masked in the binary.
#[macro_export]
macro_rules! masked {
    ($text:literal) => {{
        const MASKED: [u8; $text.len()] = $crate::utils::masked::mask($text);
        String::from_utf8($crate::utils::masked::unmask(&MASKED))
            .expect("masked literal is valid UTF-8")
    }};
}

/// Like [`masked!`](crate::masked), but returns the bytes as a `Vec<u8>`.
#[macro_export]
macro_rules! masked_bytes {
    ($text:literal) => {{
        const MASKED: [u8; $text.len()] = $crate::utils::masked::mask($text);
        $crate::utils::masked::unmask(&MASKED)
    }};
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_masked_round_trip() {
        assert_eq!(crate::masked!("beacon.dll"), "beacon.dll");
        assert_eq!(crate::masked_bytes!("%s.4444"), b"%s.4444".to_vec());
        assert_eq!(crate::masked!(""), "");
    }

    #[test]
    fn test_masked_bytes_differ_from_text() {
        let masked = super::mask::<10>("beacon.dll");
        assert_ne!(&masked, b"beacon.dll");
    }
}
