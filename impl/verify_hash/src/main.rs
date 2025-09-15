use num_bigint::BigUint;
use rsa::verify_md5_hash;

const M: &[u8] = b"Launch a missile.";
const S: &[u8] = b"8AB69AF9AE8208C491A3EEC30E3E48C133BCCD8985D3FCD4BB0F01EE9DEF7260";
const E: &[u8] = b"010001";
const N: &[u8] = b"DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5";

fn parse(b: &[u8]) -> BigUint {
    BigUint::parse_bytes(b, 16).unwrap()
}

fn main() {
    let s = parse(S);
    let e = parse(E);
    let n = parse(N);

    println!("{}", verify_md5_hash(M, &s, &e, &n));
}
