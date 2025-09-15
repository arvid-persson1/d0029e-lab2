use num_bigint::BigUint;
use rsa::{KeySet, encrypt, generate_key};

const P: &[u8] = b"F7E75FDC469067FFDC4E847C51F452DF";
const Q: &[u8] = b"E85CED54AF57E53E092113E62F436F4F";
const E: &[u8] = b"0D88C3";
const M: &[u8] = b"I owe you $2000.";

fn parse(b: &[u8]) -> BigUint {
    BigUint::parse_bytes(b, 16).unwrap()
}

fn main() {
    let p = parse(P);
    let q = parse(Q);
    let e = parse(E);

    let KeySet { d, n, .. } = generate_key(&p, &q, e).unwrap();
    let s = encrypt(M, &d, &n).unwrap();
    println!("{:X}", s);
}
