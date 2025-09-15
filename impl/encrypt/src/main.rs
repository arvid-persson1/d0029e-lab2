use num_bigint::BigUint;
use rsa::encrypt;

const M: &[u8] = b"A top secret!";
const E: &[u8] = b"010001";
const N: &[u8] = b"DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5";

fn parse(b: &[u8]) -> BigUint {
    BigUint::parse_bytes(b, 16).unwrap()
}

fn main() {
    let e = parse(E);
    let n = parse(N);

    let c = encrypt(M, &e, &n).unwrap();
    println!("{:X}", c);
}
