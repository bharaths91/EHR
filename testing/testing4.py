# pip install cryptography
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec


def generate_ecc_key_pair():
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key


def ecc_encrypt(plaintext, recipient_public_key):
    ciphertext, _ = recipient_public_key.encrypt(
        plaintext.encode('utf-8'),
        ec.ECIES(hashes.SHA256())
    )
    return ciphertext


def ecc_decrypt(ciphertext, recipient_private_key):
    plaintext = recipient_private_key.decrypt(
        ciphertext,
        ec.ECIES(hashes.SHA256())
    )
    return plaintext.decode('utf-8')


# Example usage:
if __name__ == "__main__":
    # Step 1: Generate keys
    recipient_private_key, recipient_public_key = generate_ecc_key_pair()

    # Step 2: Encryption
    plaintext_message = "Hello, ECC encryption!"
    ciphertext = ecc_encrypt(plaintext_message, recipient_public_key)

    # Step 3: Decryption
    decrypted_message = ecc_decrypt(ciphertext, recipient_private_key)

    # Output
    print("Plaintext:", plaintext_message)
    print("Ciphertext:", ciphertext)
    print("Decrypted Message:", decrypted_message)
