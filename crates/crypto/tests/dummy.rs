//! Dummy stranger notes (spec W4, audit MED-03): real v5 notes between
//! throwaway identities, so an unused slot looks like a used one.
//! Unreviewed.

use anonymum_core::SealedNote;
use anonymum_crypto::note::SEALED_NOTE_LEN;
use anonymum_crypto::{dummy_note, is_contributory_key, open_note, random_bytes, seal_note, ContactIdentity, NoteError};
use curve25519_dalek::montgomery::MontgomeryPoint;

const NET: [u8; 32] = [9; 32];
const NOW: u64 = 1_800_000_000;
/// The Noise message starts after the admission commitment (32) and the
/// ML-KEM-768 ciphertext (1,088); its first 32 bytes are the ephemeral key.
const EPHEMERAL: std::ops::Range<usize> = 1_120..1_152;

/// What a real X25519 public key always satisfies and uniform random bytes
/// fail about half the time: top bit clear, and a point on Curve25519
/// itself (`to_edwards` refuses a u-coordinate on the twist).
fn looks_like_a_curve_point(bytes: &[u8]) -> bool {
    let u: [u8; 32] = bytes.try_into().unwrap();
    u[31] & 0x80 == 0 && MontgomeryPoint(u).to_edwards(0).is_some() && is_contributory_key(&u)
}

fn real_note() -> Vec<u8> {
    let (bob, carol) = (ContactIdentity::generate_at(NOW), ContactIdentity::generate_at(NOW));
    seal_note(&NET, &bob.card(NET, 1), &carol, &carol.card(NET, 1), &[7; 96], "hi", &[0xAD; 32]).unwrap().0
}

/// (a) Exact length, not blank, fresh each time.
#[test]
fn a_dummy_note_has_the_exact_length_and_is_fresh_each_time() {
    let notes: Vec<[u8; SEALED_NOTE_LEN]> = (0..4).map(|_| dummy_note(&NET, NOW)).collect();
    assert_eq!(SEALED_NOTE_LEN, 1_795);
    for (i, note) in notes.iter().enumerate() {
        assert_eq!(note.len(), real_note().len());
        assert!(note.iter().any(|b| *b != 0), "not all zero");
        // No field is left blank: admission, ML-KEM ciphertext, Noise message.
        for field in [&note[..32], &note[32..1_120], &note[1_120..]] {
            assert!(field.iter().any(|b| *b != 0));
        }
        for other in &notes[i + 1..] {
            assert_ne!(note, other, "fresh per call");
            assert_ne!(note[..32], other[..32], "fresh admission commitment");
            assert_ne!(note[EPHEMERAL], other[EPHEMERAL], "fresh ephemeral key");
        }
    }
}

/// (b) Nobody can open it: not a stranger, not a holder of any real
/// identity, at any time.
#[test]
fn no_real_identity_can_open_a_dummy_note() {
    let note = SealedNote(dummy_note(&NET, NOW).to_vec());
    for _ in 0..8 {
        let someone = ContactIdentity::generate_at(NOW);
        for now in [NOW, NOW + 86_400] {
            assert!(matches!(open_note(&someone, &NET, &note, NOW, now), Err(NoteError::Noise(_))));
        }
    }
}

/// (c) The ephemeral key has the distribution of a real note's: a valid,
/// canonical Curve25519 point. Random bytes in the same place would give
/// themselves away.
#[test]
fn a_dummy_notes_ephemeral_key_is_a_real_curve_point() {
    for _ in 0..32 {
        let dummy = dummy_note(&NET, NOW);
        assert!(looks_like_a_curve_point(&dummy[EPHEMERAL]), "dummy");
        assert!(looks_like_a_curve_point(&real_note()[EPHEMERAL]), "real, as the reference");
    }
    // The control: of 64 random 32-byte strings, some fail the test (each
    // passes with probability about 1/4: a clear top bit and the curve, not
    // the twist). The chance that all 64 pass is about 2^-128.
    let failing = (0..64).filter(|_| !looks_like_a_curve_point(&random_bytes())).count();
    assert!(failing > 0, "the distinguisher is a real one");
}

