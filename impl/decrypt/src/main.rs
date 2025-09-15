use num_bigint::BigUint;
use rsa::decrypt;

const C: &[u8] = b"8C0F971DF2F3672B28811407E2DABBE1DA0FEBBBDFC7DCB67396567EA1E2493F";
const D: &[u8] = b"74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D";
const N: &[u8] = b"DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5";

fn parse(b: &[u8]) -> BigUint {
    BigUint::parse_bytes(b, 16).unwrap()
}

fn main() {
    let n = parse(N);
    let d = parse(D);
    let c = parse(C);

    let m = decrypt(&c, &d, &n);
    println!("{}", str::from_utf8(&m).unwrap());
}
