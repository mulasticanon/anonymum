//! The one hash function `H` the model uses, with domain separation.
//!
//! BLAKE2s-256 from the `blake2` crate (an established implementation; no
//! hand-written primitive). Every call names a domain, and every input is
//! length-prefixed, so two different (domain, fields) pairs never feed the
//! hash the same bytes. A real circuit will use whatever circuit-friendly
//! hash the cryptographer chooses (spec section 8); the model only needs a
//! collision-resistant, domain-separated stand-in.

use blake2::{Blake2s256, Digest};

pub type Hash = [u8; 32];

const PREFIX: &[u8] = b"anonymum/shielded-model/v0/";

/// `H(domain, parts...)`.
pub fn h(domain: &str, parts: &[&[u8]]) -> Hash {
    let mut hasher = Blake2s256::new();
    let tag = [PREFIX, domain.as_bytes()].concat();
    hasher.update((tag.len() as u64).to_le_bytes());
    hasher.update(&tag);
    for part in parts {
        hasher.update((part.len() as u64).to_le_bytes());
        hasher.update(part);
    }
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domains_separate_and_lengths_frame() {
        assert_ne!(h("a", &[b"x"]), h("b", &[b"x"]), "different domains");
        assert_ne!(h("a", &[b"ab", b"c"]), h("a", &[b"a", b"bc"]), "length-prefixed fields");
        assert_ne!(h("a", &[b"x"]), h("a", &[b"x", b""]), "field count matters");
        assert_eq!(h("a", &[b"x"]), h("a", &[b"x"]), "deterministic");
    }
}
