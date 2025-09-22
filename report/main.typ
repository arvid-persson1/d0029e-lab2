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
  
=

==

Implementation of the key generation function is shown below.

The code is written in Rust. For all future tasks, we will assume `num-bigint`, `md5`, `num-traits` and `thiserror` as dependencies, and omit some imports, type definitions and functions. For some tasks, we will also omit the executable scripts and show only the library code. Everything is available on #link("https://github.com/arvid-persson1/d0029e-lab2/")[the Github repository for this report].

```rs
pub type Key = BigUint;
pub type Modulo = BigUint;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct KeySet {
    pub e: Key,
    pub d: Key,
    pub n: Modulo,
}

pub fn generate_key(p: &BigUint, q: &BigUint, e: BigUint)
    -> Result<KeySet, KeygenError>
{
    let n = p * q;
    let phi = (p - 1u8) * (q - 1u8);

    (e < phi && e > BigUint::one())
        .then(|| e.modinv(&phi))
        .ok_or(KeygenError::ExponentOutOfRange)
        .transpose()
        .ok_or(KeygenError::InvalidExponent)
        .flatten()
        .map(|d| KeySet { e, d, n })
}
```

Using the given parameters, we generate the keys:

```sh
generate
>>> e: 0xD88C3
>>> d: 0x3587A24598E5F2A21DB007D89D18CC50ABA5075BA19A33890FE7C28A9B496AEB
>>> n: 0xE103ABD94892E3E74AFD724BF28E78366D9676BCCC70118BD0AA1968DBB143D1
```

==

Implementation of encryption is shown below.

```rs
pub type Ciphertext = BigUint;

pub fn encrypt(m: &[u8], e: &Key, n: &Modulo) -> Result<Ciphertext, EncryptionError> {
    let m = BigUint::from_bytes_be(m);
    (m < *n)
        .then(|| m.modpow(e, n))
        .ok_or(EncryptionError::MessageTooLarge)
}
```

Encrypting the given plaintext with the given parameters, we find the ciphertext:

```sh
encrypt
>>> 0x6FB078DA550B2650832661E14F4F8D2CFAEF475A0DF3A75CACDC5DE5CFC5FADC
```

==

Implementation of decryption is shown below.

```rs
pub fn decrypt(c: &Ciphertext, d: &Key, n: &Modulo) -> Vec<u8> {
    c.modpow(d, n).to_bytes_be()
}
```

Decrypting the given ciphertext with the given parameters, we find the plaintext:

```sh
decrypt
>>> Password is dees
```

=

==

Signing a message is done using the `encrypt` function, but using the private key instead of the public key. Encrypting the given plaintext "I owe you \$2000." using the given parameters, we find the signature. The altered plaintext "I owe you \$3000.", differing by only one bit, as expected produces an entirely different signature:

```sh
# "I owe you $2000"
sign
>>> 0x2FA22F587025A7AE76B896F7390AF79443017DE885D08010188558274F3ACBF3
# "I owe you $3000"
sign
>>> 0x8A6F408041CF163AA5D0C317B21483473A91FDFB03FADA7D35CD13F20DD71141
```

==

Verifying a signature is done using the `decrypt` function, but using the public key instead of the private key. Checking the given signature using the given parameters, we find that it is valid. Changing the last byte of the signature to `3F` instead of `2F`, differing by only one bit, as expected we find that the signature is no longer valid.

```sh
# ...2F
sign
>>> true
# ...3F
sign
>>> false
```

==

Signing a hash works exactly like signing the message directly, except that we pass the message to the hash function before encrypting. Implementation is shown below.

```rs
use md5::compute as md5;

pub fn sign_md5_hash(m: &[u8], d: &Key, n: &Modulo)
    -> Result<Ciphertext, EncryptionError>
{
    encrypt(&*md5(m), d, n)
}
```

Using with the same inputs, we find the signature:

```sh
sign_hash
>>> 0x3958CF237CB04FBEF3CED80E37BBC9F74E573FC04ECDBA71373679B72F830ED0

```

==

Verifying a hash works exactly like verifying the message directly, except that we also hash the message and instead compare the hashes, since hashing is not (uniquely or easily) invertible. Implementation is shown below.

```rs
pub fn verify_md5_hash(m: &[u8], s: &Ciphertext, e: &Key, n: &Modulo) -> bool {
    decrypt(s, e, n) == *md5(m)
}
```

Using the same inputs, we check the signature:

```sh
verify_hash
>>> true
```

=

We found that #link("canvas.ltu.se")[Canvas] uses the desired type of certificate. Using the given commands, we download the certificate and identify, extract and process the required parts:

```sh
openssl s_client -connect canvas.ltu.se:443 -showcerts > cert
head -36 cert | tail -29 > c0.pem
head -69 cert | tail -29 > c1.pem

openssl x509 -in c1.pem -noout -modulus | grep -Po '^Modulus=\K[0-9A-F]+$'
    | tr -d "\n" > modulo

openssl x509 -in c1.pem -text -noout | grep -Po
    '^\s*Exponent: \d+ \(0x\K[0-9A-Fa-f]+(?=\)$)' | tr -d "\n" > public_key

openssl x509 -in c0.pem -text -noout | tail -15 | tr -d "[:space:]:" > signature

openssl asn1parse -i -in c0.pem -strparse 4 -out /dev/stdout -noout | sha256sum
    | head -c 64 > body_hash
```

To verify the signature, we first ensure that it is in the proper RSASSA-PKCS1-v1_5 format, then compare the hashes. We should see the following:

+ Two bytes containing `0x0001`, indicating the start of the encoded message.
+ At least 8 padding bytes, all containing `0xff`.
+ A byte containing `0x00`, indicating the end of the padding.
+ The SHA256 prefix: `0x3031300d060960864801650304020105000420`.
+ The message digest.

Implementation is shown below.

```rs
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
```

Running to verify:

```sh
run.sh
>>> true
```

=

==

MD5 works on 64-byte (512-bit) blocks. The prefix is as such expected to be an integer number of blocks, so that the collsion tool can concatenate one or more blocks to it to create the collision files. The practical solution to this is of course to pad the prefix file to a multiple of 64 bytes. If our prefix is already a multiple of 64 bytes, no padding is needed.

How padding is done is an implementation detail but could be crucial for our use case. If, for example, we are working with text, a series of null (`0x00`) bytes could be acceptable as many text editors would simply ignore these. If we are working with executable code, however, stray bytes could change the behavior of the program or make it not run at all.

We can examine how `md5collgen` handles padding by creating some collision files. The contents of our prefixes are not important, so we generate some random bytes as prefixes:

```sh
head -c 60 /dev/urandom | md5collgen -p /dev/stdin -o 60_1.bin 60_2.bin
head -c 64 /dev/urandom | md5collgen -p /dev/stdin -o 64_1.bin 64_2.bin
wc -c *.bin
>>> 192 60_1.bin
>>> 192 60_2.bin
>>> 192 64_1.bin
>>> 192 64_2.bin
>>> ...
tail -c +61 64_0.bin | head -4 | hexdump
>>> 0000000 0000 0000                              
>>> ...
```

We make two observations:

+ The collision files are 192 bytes---3 blocks---long, meaning 2 blocks have been added. It may or may not be possible to always ensure a collision by appending only one block, but this could be more expensive or complex.

+ The padding consists of null bytes.

#counter(heading).step(level: 2)
==

Our strategy, at a high level, is to create a program that compares two strings of arbitrary data, executing one branch in the case that they are identical, and another if they aren't. We hope to be able to modify the files such that the strings are identical in only one version but the MD5 hashes of the programs are still the same.

We start with the following Python program:

```py
x="xxx..." # 127 x's.
y="yyy..." # 127 y's.
if x == y:
    print("Hello, World!")
else:
    print("Goodbye, World!")
```

We can't work with the source code directly as our process will include embedding randomly generated bytes, which would result in invalid Python syntax. Instead we first compile the program to the intermediate bytecode representation used by CPython. This compilation seems to include at least some basic optimization steps, as having the strings be identical in the source code results in only one string in program memory, presumably with both `x` and `y` pointing to the same location as they are never written through.

127 bytes were chosen so that no matter where the strings are placed in the bytecode representation, there will be a contigous 64-byte block contained entirely within the string. If we expect $n$ blocks, we would make these $2 dot.op 64n - 1$ bytes. The contents are simply placeholders to make them easy to identify when viewing the bytecode with a hex editor.

Let $P$ be the prefix ending before the block contained within the `x`-string. Next, generate the collision blocks and let these be $p, q$. Let $M$ be the "middle" of the program starting after the end of the block following $P$ and containing as many bytes of the `y`-string as $P$ contains bytes of the `x`-string. In our case, we found the `y`-string to be placed after the `x`-string in memory, but we could simply swap the order if they were the other way around. Let $S$ be the suffix of the file, starting after the (possibly misaligned) block following $M$. Having identified these segments, we can replace all `y` bytes in the `y`-string with `x`.

Let $||$ denote concatenation. Now, create the following files:
- $P || p || M || p || S$. This is our benign program.
- $P || q || M || p || S$. This is our malicious program.

Since $P || p$ and $P || q$ have the same MD5 hashes, and the tails are identical, we know that the full files also have the same hashes (not necessarily the same as just the heads). We verify:

```sh
coll
python benign.pyc
>>> Hello, World!
python malicious.pyc
>>> Goodbye, World!
md5sum benign.pyc malicious.pyc
>>> 9e78a947f452a8448b478bef7c544359  benign.pyc
>>> 9e78a947f452a8448b478bef7c544359  malicious.pyc
```

Implementation below:

```rs
use std::{
    fs::{File, read, write},
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
    process::{Command, Stdio},
};

const BLOCK_SIZE: usize = 128;

fn find(haystack: &[u8], needle: &[u8]) -> usize {
    haystack
        .windows(needle.len())
        .position(|w| w == needle)
        .unwrap()
}

fn read_from(path: impl AsRef<Path>, start: u64) -> Vec<u8> {
    let mut file = File::open(path).unwrap();
    file.seek(SeekFrom::Start(start)).unwrap();

    let mut buf = Vec::new();
    file.read_to_end(&mut buf).unwrap();
    buf
}

fn main() {
    let status = Command::new("python")
        .args(&["-m", "py_compile", "source.py"])
        .status()
        .unwrap();
    assert!(status.success());
    let mut pyc = read("__pycache__/source.cpython-313.pyc").unwrap()

    let len_str = BLOCK_SIZE * 2 - 1;
    let start_x = find(&pyc, &vec![b'x'; len_str]);
    let start_y = find(&pyc, &vec![b'y'; len_str]);
    let prefix_len = start_x.next_multiple_of(BLOCK_SIZE);

    let offset = start_y + prefix_len - start_x;
    pyc[start_y..offset].fill(b'x');
    pyc[offset + BLOCK_SIZE..start_y + len_str].fill(b'x');

    let mut child = Command::new("md5collgen")
        .args(&["-p", "/dev/stdin", "-o", "p", "q"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(&pyc[..prefix_len])
        .unwrap();
    let status = child.wait().unwrap();
    assert!(status.success());

    let p = read_from("p", prefix_len as u64);
    let q = read_from("q", prefix_len as u64);
    assert_eq!(p.len(), BLOCK_SIZE);
    assert_eq!(q.len(), BLOCK_SIZE);

    pyc[offset..offset + BLOCK_SIZE].copy_from_slice(&p);
    pyc[prefix_len..prefix_len + BLOCK_SIZE].copy_from_slice(&p);
    write("benign.pyc", &pyc).unwrap();
    pyc[prefix_len..prefix_len + BLOCK_SIZE].copy_from_slice(&q);
    write("malicious.pyc", &pyc).unwrap();
}
```
