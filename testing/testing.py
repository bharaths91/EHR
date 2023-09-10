from hashlib import sha256, md5
import ecdsa
from ecdsa import SigningKey, VerifyingKey


def key_generation():
    private_key = SigningKey.generate(curve=ecdsa.SECP256k1)
    string_private_key = private_key.to_string()
    public_key = private_key.get_verifying_key()  # This verifying key is the public key.
    string_public_key = public_key.to_string()
    print("private_key", private_key)
    print("string_private_key", string_private_key)
    print("public_key", public_key)
    print("string_public_key", string_public_key)
    return string_private_key, string_public_key


# def SignUserFile(private_key):
#     #   User's file or Data acceptance begins.
#     with open('testing_file.txt', 'r') as Ufile:
#         dataFile = Ufile.read()
#         hashedFile = (sha256(dataFile.encode())).hexdigest()  # Encode and Hash the file.
#
#     sgkey = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1)
#     digitalSig = sgkey.sign(hashedFile.encode())  # This throws error if not encoded.
#     print('digitalSig', digitalSig)


def SignUserFile(input_data, private_key):
    dataFile = input_data

    hashedFile = (sha256(dataFile.encode())).hexdigest()  # Encode and Hash the file.
    sgkey = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1)
    digitalSig = sgkey.sign(hashedFile.encode())  # This throws error if not encoded.
    print('hashedFile', hashedFile)
    print("--------------------")
    print('digitalSig', digitalSig)
    print("--------------------")
    return hashedFile, digitalSig


def verifyFile(public_key, d_s, hashed_data):
    verificationKey = ecdsa.VerifyingKey.from_string(public_key, curve=ecdsa.SECP256k1)
    string_verification_key = verificationKey.to_string()
    print("string_verification_key", string_verification_key)
    final = verificationKey.verify(d_s, hashed_data.encode())
    a = string_verification_key.decode(encoding='unicode_escape')
    print("a", a)
    # final1 = verificationKey.verify(d_s, hashed_data.encode())
    # assert verificationKey.verify(d_s, hashed_data.encode()), "Sorry! Verification failed."
    print("final", final)


# keys = key_generation()
#
# i_p = input("Enter something: ")
#
# enc = SignUserFile(i_p, keys[0])
#
# verifyFile(keys[1], enc[1], enc[0])

keys = key_generation()
