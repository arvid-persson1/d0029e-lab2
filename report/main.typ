#text(2em)[D0029E Lab 2 - Group Green M 3]

#show link: underline

Members:
- Arvid Persson
- Joel Andersson
- Rasmus Engström

#set heading(
  numbering: (..n) => {
    let number = n.pos().map(str).join(".")
    [Task #number]
  },
  supplement: [],
)
  
#counter(heading).update(1)
==

Implementation of the key generation function in Rust is shown below. For all future tasks, we will assume `num-bigint`, `md5`, `num-traits` and `thiserror` as dependencies, and omit imports, type definitions and functions already shown in earlier tasks. Full code is available on #link("https://github.com/arvid-persson1/d0029e-lab2/")[the Github repository for this report].

```rs
use num_bigint::BigUint;
use num_traits::identities::One;
use thiserror::Error;

pub type Key = BigUint;
pub type Modulo = BigUint;

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

pub fn generate_key(p: &BigUint, q: &BigUint, e: BigUint)
    -> Result<KeySet, KeygenError>
{
    let n = p * q;
    let phi = (p - 1u8) * (q - 1u8);

    if e < phi && e > BigUint::one() {
        e.modinv(&phi)
            .ok_or(KeygenError::InvalidExponent)
            .map(|d| KeySet { e, d, n })
    } else {
        Err(KeygenError::ExponentOutOfRange)
    }
}
```
