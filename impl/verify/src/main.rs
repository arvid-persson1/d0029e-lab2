use num_bigint::BigUint;
use rsa::decrypt;

const M: &[u8] = b"Launch a missile.";
const S: &[u8] = b"643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6802F";
const E: &[u8] = b"010001";
const N: &[u8] = b"AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115";

fn parse(b: &[u8]) -> BigUint {
    BigUint::parse_bytes(b, 16).unwrap()
}

fn main() {
    let s = parse(S);
    let e = parse(E);
    let n = parse(N);

    println!("{}", decrypt(&s, &e, &n) == M);
}
