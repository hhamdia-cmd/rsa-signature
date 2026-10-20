# RSA digital signature demonstration

Python implementation for Software Security (SDEV 4303), Chapter 02.

## Run

```sh
python -m pip install -r requirements.txt
python rsa_signature.py
python -m unittest -v
```

The tested environment is Python 3.12.14 with cryptography 50.0.2.

The demonstration generates a 3072-bit RSA key, signs a message with RSA-PSS and
SHA-256, and checks the original message, a changed recipient, a modified
signature, and a different verification key. It also shows that replaying a valid
message/signature pair still passes cryptographic verification. A real receiver
would need an authenticated transaction identifier and duplicate tracking to
reject replays.

Keys exist only in process memory. The demonstration does not print, export, or
save private keys. Its generated identity has no certificate or external trust
binding. This is a classroom demonstration, rather than a complete payment or
identity system.

Implementation reference: [cryptography RSA documentation](https://cryptography.io/en/stable/hazmat/primitives/asymmetric/rsa/).
