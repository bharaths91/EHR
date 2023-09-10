# import binascii
import hashlib
import secrets
from Crypto.Cipher import AES
from tinyec import registry
import pickle as pkl
curve = registry.get_curve('brainpoolP256r1')


def generate_keys():
    private_Key = secrets.randbelow(curve.field.n)
    public_key = private_Key * curve.g
    return private_Key, public_key


def ecc_point_to_256_bit_key(point):
    sha = hashlib.sha256(int.to_bytes(point.x, 32, 'big'))
    sha.update(int.to_bytes(point.y, 32, 'big'))
    return sha.digest()


def encrypt_AES_GCM(msg, secretKey):
    aesCipher = AES.new(secretKey, AES.MODE_GCM)
    ciphertext, authTag = aesCipher.encrypt_and_digest(msg)
    return ciphertext, aesCipher.nonce, authTag


def encrypt_ECC(msg, pubKey):
    msg = bytes(msg, 'utf-8')
    ciphertextPrivKey = secrets.randbelow(curve.field.n)
    sharedECCKey = ciphertextPrivKey * pubKey
    secretKey = ecc_point_to_256_bit_key(sharedECCKey)
    ciphertext, nonce, authTag = encrypt_AES_GCM(msg, secretKey)
    ciphertextPubKey = ciphertextPrivKey * curve.g
    return ciphertext, nonce, authTag, ciphertextPubKey


def decrypt_AES_GCM(ciphertext, nonce, authTag, secretKey):
    aesCipher = AES.new(secretKey, AES.MODE_GCM, nonce)
    plaintext = aesCipher.decrypt_and_verify(ciphertext, authTag)
    return plaintext


def decrypt_ECC(encrypted_msg, p2_key):
    print(p2_key)
    # p2_key = p2_key * curve.g
    (ciphertext, nonce, authTag, ciphertextPubKey) = encrypted_msg
    sharedECCKey = p2_key * ciphertextPubKey
    secretKey = ecc_point_to_256_bit_key(sharedECCKey)
    plaintext = decrypt_AES_GCM(ciphertext, nonce, authTag, secretKey)
    return plaintext


keys = generate_keys()
pri_key = keys[0]
pub_key = keys[1]
print(pri_key)
print("--------------------")
print(pub_key)

with open("../key.txt", "w") as key_file:
    key_file.write(str(pri_key))

msg = input("Enter text: ")
encrypted = encrypt_ECC(msg, pub_key)
print("encrypted:", encrypted)


with open(file="msg.pkl", mode="wb") as file:
    pkl.dump(obj=encrypted, file=file)

with open(file="msg.pkl", mode="rb") as file:
    res_msg = pkl.load(file=file)

with open("../key.txt", "r") as key_file1:
    new_pri_key = int(key_file1.read())


decrypted = decrypt_ECC(res_msg, new_pri_key)
print("Decrypted:", decrypted.decode())
