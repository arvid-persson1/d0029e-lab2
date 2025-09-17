// WARN: this library should use a BigInt library adapted for cryptographic usage, with
// constant-time operations. However, the `crypto_bigint` crate does not support inverse modulo
// operations with even exponents, but instead falls back to `num_bigint` implementations. Upon
// examination, we find that even the `rsa` crate depends on the `num_*`-crates, likely using some
// other method to prevent timing attacks.
use md5::compute as md5;
use num_bigint::BigUint;
use num_traits::identities::One;
use thiserror::Error;

pub type Key = BigUint;
pub type Modulo = BigUint;
pub type Ciphertext = BigUint;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct KeySet {
    pub e: Key,
    pub d: Key,
    pub n: Modulo,
}

#[derive(Clone, Debug, Error, PartialEq, Eq, Hash)]
pub enum KeygenError {
    #[error("Exponent must be between 1 and ϕ(n)")]
    ExponentOutOfRange,
    #[error("Exponent must have a modular inverse in n")]
    InvalidExponent,
}

pub fn generate_key(p: &BigUint, q: &BigUint, e: BigUint) -> Result<KeySet, KeygenError> {
    let n = p * q;
    let phi = (p - 1u8) * (q - 1u8);

    if e > BigUint::one() && e < phi {
        let d = e.modinv(&phi).ok_or(KeygenError::InvalidExponent)?;
        Ok(KeySet { e, d, n })
    } else {
        Err(KeygenError::ExponentOutOfRange)
    }
}

#[derive(Clone, Debug, Error, PartialEq, Eq, Hash)]
pub enum EncryptionError {
    #[error("Message must be smaller than n")]
    MessageTooLarge,
}

pub fn encrypt(m: &[u8], e: &Key, n: &Modulo) -> Result<Ciphertext, EncryptionError> {
    let m = BigUint::from_bytes_be(m);
    if m < *n {
        Ok(m.modpow(e, n))
    } else {
        Err(EncryptionError::MessageTooLarge)
    }
}

pub fn decrypt(c: &Ciphertext, d: &Key, n: &Modulo) -> Vec<u8> {
    c.modpow(d, n).to_bytes_be()
}

pub fn sign_md5_hash(m: &[u8], d: &Key, n: &Modulo) -> Result<Ciphertext, EncryptionError> {
    // MD5 digests are a fixed 128 bits, but this may still be too large if n is small.
    encrypt(&*md5(m), d, n)
}

pub fn verify_md5_hash(m: &[u8], s: &Ciphertext, e: &Key, n: &Modulo) -> bool {
    decrypt(s, e, n) == *md5(m)
}
