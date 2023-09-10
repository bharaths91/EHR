import binascii
import hashlib
import secrets
from Crypto.Cipher import AES
from tinyec import registry
# from nacl.public import PrivateKey   # pip install pynacl


curve = registry.get_curve('brainpoolP256r1')


# def generate_keys():
#     privKey = PrivateKey.generate()
#     pubKey = privKey.public_key
#     a = binascii.hexlify(bytes(privKey))
#     b = binascii.hexlify(bytes(pubKey))
#     c = binascii.unhexlify(bytes(a))
#     d = binascii.unhexlify(bytes(b))
#     print("privKey:", a)
#     print("pubKey: ", b)
#     print("privKey:", c)
#     print("pubKey: ", d)
#     return privKey, pubKey


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
    # (ciphertext, nonce, authTag, ciphertextPubKey) = encrypted_msg.values()
    (ciphertext, nonce, authTag, ciphertextPubKey) = encrypted_msg
    sharedECCKey = p2_key * ciphertextPubKey
    secretKey = ecc_point_to_256_bit_key(sharedECCKey)
    plaintext = decrypt_AES_GCM(ciphertext, nonce, authTag, secretKey)
    return plaintext


keys = generate_keys()
pri_key = keys[0]
pub_key = keys[1]
print(pri_key)
print(pub_key)


msg = input("Enter text: ")
encrypted = encrypt_ECC(msg, pub_key)
print("Decrypted:", encrypted)
key = encrypted[3]


decrypted = decrypt_ECC(encrypted, pri_key)
print("Decrypted:", decrypted.decode())


# from Crypto.PublicKey import ECC
#
# key = ECC.generate(curve='P-256')
#
# f = open('myprivatekey.pem','wt')
# f.write(key.export_key(format='PEM'))
# f.close()
#
# f = open('myprivatekey.pem','rt')
# key = ECC.import_key(f.read())







# def encryption(text, pu_key):
#     msg = bytes(text, 'utf-8')
#     encryptedMsg = encrypt_ECC(msg, pu_key)
#     encryptedMsgObj = {
#         'ciphertext': binascii.hexlify(encryptedMsg[0]),
#         'nonce': binascii.hexlify(encryptedMsg[1]),
#         'authTag': binascii.hexlify(encryptedMsg[2]),
#         'ciphertextPubKey': hex(encryptedMsg[3].x) + hex(encryptedMsg[3].y % 2)[2:]
#     }
#
#     key_list = encryptedMsgObj.keys()
#     val_list = encryptedMsgObj.values()
#     val_list = [i.decode() if idx != 3 else i for idx, i in enumerate(val_list)]
#
#     key_str = ' '.join(key_list)
#     val_str = ' '.join(val_list)
#     final_string = key_str + '-' + val_str
#     return final_string


# def decryption(enc_text, p1_key):
#     enc_text = enc_text.split('-')
#     k_list = enc_text[0].split(' ')
#     v_list = enc_text[1].split(' ')
#     v_list = [i.encode() if idx != 3 else i for idx, i in enumerate(v_list)]
#     encryptedMsg = {k: v for (k, v) in zip(k_list, v_list)}
#     # decrypted_text = decrypt_ECC(encryptedMsg, p1_key)
#     decrypted_text = decrypt_ECC(new_encryptedMsgObj, p1_key)
#     return decrypted_text


# keys = generate_keys()
# pri_key = keys[0]
# pub_key = keys[1]

# text = input("Enter text for encryption: ")
# encrypted = encryption(text, pub_key)
#
# print("-----------------")
# print(encrypted)
# print(pri_key)
# print(type(pri_key))
#
# decrypted = decryption(encrypted, pri_key)
# print("Decrypted", decrypted)
