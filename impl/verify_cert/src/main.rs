use num_bigint::BigUint;
use rsa::decrypt;

const S: &[u8] = include_bytes!("../signature");
const E: &[u8] = include_bytes!("../public_key");
const N: &[u8] = include_bytes!("../modulo");
const H: &[u8] = include_bytes!("../body_hash");

const SHA256_PREFIX: &[u8] = b"3031300d060960864801650304020105000420";

fn parse(b: &[u8]) -> BigUint {
    BigUint::parse_bytes(b, 16).unwrap()
}

fn main() {
    let s = parse(S);
    let e = parse(E);
    let n = parse(N);
    let h = parse(H);

    // Expected format: [0x00, 0x01, 0xff{8,}, 0x00, SHA256_PREFIX, digest]
    let m = decrypt(&s, &e, &n);
    let mut it = m.iter().copied().enumerate().peekable();

    // Leading zero byte might have been stripped.
    it.next_if(|(_, b)| *b == 0x00);
    assert_eq!(it.next().unwrap().1, 0x01);

    let mut padding_bytes = 0;
    for (_, b) in it.by_ref() {
        match b {
            0xff => padding_bytes += 1,
            0x00 => break,
            _ => panic!(),
        }
    }
    assert!(padding_bytes >= 8);
    let content_start = it.next().unwrap().0;

    let prefix = parse(SHA256_PREFIX).to_bytes_be();
    let digest = m[content_start..].strip_prefix(&prefix[..]).unwrap();

    println!("{}", BigUint::from_bytes_be(digest) == h);
}
