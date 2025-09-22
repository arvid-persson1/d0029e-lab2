use num_bigint::BigUint;
use rsa::sign_md5_hash;

const M: &[u8] = b"Launch a missile.";
const D: &[u8] = b"74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D";
const N: &[u8] = b"DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5";

fn parse(b: &[u8]) -> BigUint {
    BigUint::parse_bytes(b, 16).unwrap()
}

fn main() {
    let d = parse(D);
    let n = parse(N);

    let s = sign_md5_hash(M, &d, &n).unwrap();
    println!("{:#X}", s);
}
