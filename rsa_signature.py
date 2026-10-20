"""RSA-PSS digital signature demonstration for SDEV 4303, Chapter 02.

The private keys remain in memory. This program never prints or saves them.
"""

import argparse
import json
import platform

import cryptography
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def pss_padding():
    """Use SHA-256 for MGF1 and a 32-byte salt."""
    return padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=hashes.SHA256.digest_size,
    )


def generate_private_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=3072)


def sign_message(private_key, message: bytes) -> bytes:
    """Sign the exact message bytes using the signer's private key."""
    return private_key.sign(message, pss_padding(), hashes.SHA256())


def verify_signature(public_key, message: bytes, signature: bytes) -> bool:
    """Accept a signature only when it matches both the message and the key."""
    try:
        public_key.verify(signature, message, pss_padding(), hashes.SHA256())
    except InvalidSignature:
        return False
    return True


def run_demo() -> dict:
    private_key = generate_private_key()
    public_key = private_key.public_key()
    message = b"Transfer $1000 to Mark"
    signature = sign_message(private_key, message)

    changed_signature = bytes([signature[0] ^ 1]) + signature[1:]
    other_public_key = generate_private_key().public_key()
    cases = [
        ("Original message", message, signature, public_key, True),
        ("Modified message", b"Transfer $1000 to Oscar", signature, public_key, False),
        ("Modified signature", message, changed_signature, public_key, False),
        ("Different public key", message, signature, other_public_key, False),
        ("Replay of valid pair", message, signature, public_key, True),
    ]
    results = []
    for label, data, candidate, key, expected in cases:
        accepted = verify_signature(key, data, candidate)
        results.append({"case": label, "accepted": accepted, "expected": expected})

    return {
        "python": platform.python_version(),
        "cryptography": cryptography.__version__,
        "scheme": "RSA-PSS / SHA-256 / MGF1-SHA-256 / 32-byte salt",
        "key_bits": private_key.key_size,
        "signature_bytes": len(signature),
        "message": message.decode("utf-8"),
        "cases": results,
        "all_expected": all(r["accepted"] == r["expected"] for r in results),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="Print structured results")
    args = parser.parse_args()
    result = run_demo()
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print("RSA DIGITAL SIGNATURE DEMONSTRATION")
        print(f"Python: {result['python']}   cryptography: {result['cryptography']}")
        print(f"Scheme: {result['scheme']}")
        print(f"RSA key: {result['key_bits']} bits")
        print(f"Signature: {result['signature_bytes']} bytes")
        print(f"Message: {result['message']}")
        print()
        for row in result["cases"]:
            status = "ACCEPTED" if row["accepted"] else "REJECTED"
            check = "PASS" if row["accepted"] == row["expected"] else "FAIL"
            print(f"[{check}] {row['case']:<24} {status}")
        print("\nA valid signature alone does not reject a replay.")
        print("Private keys were kept in memory and were not saved or displayed.")
    return 0 if result["all_expected"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
