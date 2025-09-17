#!/usr/bin/env python3
from binascii import unhexlify, hexlify
import sys

def readhex(path):
    with open(path, 'r') as f:
        return ''.join(f.read().split())

n_hex = readhex('modulus')
e_hex = readhex('public_key')
sig_hex = readhex('signature')
body_hash_hex = readhex('body_hash')

n = int(n_hex, 16)
e = int(e_hex, 16)
sig = int(sig_hex, 16)
body_hash = unhexlify(body_hash_hex)

k = (n.bit_length() + 7) // 8  # modulus length in bytes

# Recover EM = s^e mod n as bytes of length k
m = pow(sig, e, n)
em = m.to_bytes(k, 'big')

# Basic checks for PKCS#1 v1.5 structure
if em[0] != 0x00 or em[1] != 0x01:
    print("FAIL: EM does not start with 0x00 0x01 (not PKCS#1 v1.5).")
    sys.exit(1)

# find 0x00 separator after 0xFF padding
try:
    sep_idx = em.index(b'\x00', 2)
except ValueError:
    print("FAIL: No 0x00 separator found after padding.")
    sys.exit(1)

ps = em[2:sep_idx]
if any(x != 0xFF for x in ps) or len(ps) < 8:
    print("FAIL: Padding string PS is invalid (must be >=8 bytes of 0xFF).")
    sys.exit(1)

T = em[sep_idx+1:]  # DigestInfo

# DigestInfo prefix for SHA-256 (ASN.1 DER):
# 3031300d060960864801650304020105000420  ||  H (32 bytes)
sha256_prefix = unhexlify('3031300d060960864801650304020105000420')

if not T.startswith(sha256_prefix):
    print("FAIL: DigestInfo prefix != SHA-256 prefix.")
    print("Recovered T (hex):", hexlify(T).decode())
    sys.exit(1)

recovered_digest = T[len(sha256_prefix):]
if recovered_digest != body_hash:
    print("FAIL: Digest in signature does NOT match body_hash.")
    print("expected:", body_hash_hex)
    print("recovered:", hexlify(recovered_digest).decode())
    sys.exit(1)

print("OK: signature is a valid RSA PKCS#1-v1.5 signature over the TBSCertificate hash (SHA-256).")

