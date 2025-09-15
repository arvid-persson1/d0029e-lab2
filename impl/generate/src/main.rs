use num_bigint::BigUint;
use rsa::{KeySet, generate_key};

const P: &[u8] = b"F7E75FDC469067FFDC4E847C51F452DF";
const Q: &[u8] = b"E85CED54AF57E53E092113E62F436F4F";
const E: &[u8] = b"0D88C3";

fn parse(b: &[u8]) -> BigUint {
    BigUint::parse_bytes(b, 16).unwrap()
}

fn main() {
    let p = parse(P);
    let q = parse(Q);
    let e = parse(E);

    let KeySet { e, d, n } = generate_key(&p, &q, e).unwrap();
    println!("e: {:X}\nd: {:X}\nn: {:X}", e, d, n);
}
