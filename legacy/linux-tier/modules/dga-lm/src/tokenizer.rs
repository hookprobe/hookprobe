//! Fixed 40-symbol character tokenizer for the DGA classifier.
//!
//! Vocabulary (index -> class): `0`=PAD, `1..=26`=`a..z` (case-folded), `27..=36`=`0..9`,
//! `37`=`-`, `38`=`.`, `39`=UNK (anything else, incl. non-ASCII bytes). Domains are
//! lowercased, truncated/right-padded to [`MAX_LEN`] characters (left-aligned — the
//! left-hand labels of a domain carry the DGA signal; a long suffix like
//! `.example.co.uk` truncating off the end is the conservative choice).

/// Vocabulary size (see the module doc for the index -> class mapping).
pub const VOCAB: usize = 40;
/// Fixed input length in characters. Domains are truncated/padded to this.
pub const MAX_LEN: usize = 24;

const UNK: u8 = 39;
const PAD: u8 = 0;

/// Map one ASCII byte (already lowercased by the caller) to its vocabulary index.
fn char_to_id(c: u8) -> u8 {
    match c {
        b'a'..=b'z' => 1 + (c - b'a'),
        b'0'..=b'9' => 27 + (c - b'0'),
        b'-' => 37,
        b'.' => 38,
        _ => UNK,
    }
}

/// Tokenize `domain` into a fixed [`MAX_LEN`]-length array of vocabulary indices.
/// Non-ASCII bytes map to UNK; uppercase ASCII is folded to lowercase first.
pub fn tokenize(domain: &str) -> [u8; MAX_LEN] {
    let mut out = [PAD; MAX_LEN];
    for (i, b) in domain.bytes().take(MAX_LEN).enumerate() {
        out[i] = char_to_id(b.to_ascii_lowercase());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_letters_map_1_to_26() {
        assert_eq!(char_to_id(b'a'), 1);
        assert_eq!(char_to_id(b'z'), 26);
    }

    #[test]
    fn digits_map_27_to_36() {
        assert_eq!(char_to_id(b'0'), 27);
        assert_eq!(char_to_id(b'9'), 36);
    }

    #[test]
    fn hyphen_and_dot_have_own_slots() {
        assert_eq!(char_to_id(b'-'), 37);
        assert_eq!(char_to_id(b'.'), 38);
    }

    #[test]
    fn unknown_byte_maps_to_unk() {
        assert_eq!(char_to_id(b'_'), UNK);
        assert_eq!(char_to_id(b'!'), UNK);
    }

    #[test]
    fn short_domain_is_pad_filled() {
        let t = tokenize("ab");
        assert_eq!(t[0], 1);
        assert_eq!(t[1], 2);
        assert_eq!(t[2], PAD);
        assert_eq!(t[MAX_LEN - 1], PAD);
    }

    #[test]
    fn long_domain_is_truncated() {
        let long = "a".repeat(MAX_LEN + 10);
        let t = tokenize(&long);
        assert_eq!(t.len(), MAX_LEN);
        assert!(t.iter().all(|&x| x == 1));
    }

    #[test]
    fn uppercase_is_folded() {
        assert_eq!(tokenize("AB")[0], tokenize("ab")[0]);
    }
}
