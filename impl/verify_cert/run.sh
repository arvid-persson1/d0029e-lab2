openssl s_client -connect canvas.ltu.se:443 -showcerts > cert 2> /dev/null < /dev/null

head -36 cert | tail -29 > c0.pem
head -69 cert | tail -29 > c1.pem

openssl x509 -in c1.pem -noout -modulus | grep -Po '^Modulus=\K[0-9A-F]+$' | tr -d "\n" > modulo
openssl x509 -in c1.pem -text -noout | grep -Po '^\s*Exponent: \d+ \(0x\K[0-9A-Fa-f]+(?=\)$)' | tr -d "\n" > public_key
openssl x509 -in c0.pem -text -noout | tail -15 | tr -d "[:space:]:" > signature
openssl asn1parse -i -in c0.pem -strparse 4 -out /dev/stdout -noout | sha256sum | head -c 64 > body_hash

../target/release/verify_cert 2> /dev/null || cargo run
