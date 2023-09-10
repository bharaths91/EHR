import binascii
import hashlib
import secrets
from Crypto.Cipher import AES
from tinyec import registry
from Crypto.PublicKey import ECC

curve = registry.get_curve('brainpoolP256r1')


def generate_keys():
    private_Key = secrets.randbelow(curve.field.n)
    public_key = private_Key * curve.g
    print(private_Key, public_key)
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
    ciphertextPrivKey = secrets.randbelow(curve.field.n)
    sharedECCKey = ciphertextPrivKey * pubKey
    secretKey = ecc_point_to_256_bit_key(sharedECCKey)
    ciphertext, nonce, authTag = encrypt_AES_GCM(msg, secretKey)
    ciphertextPubKey = ciphertextPrivKey * curve.g
    return ciphertext, nonce, authTag, ciphertextPubKey


def encryption(text, pu_key):
    msg = bytes(text, 'utf-8')
    encryptedMsg = encrypt_ECC(msg, pu_key)
    # print(encryptedMsg[3])
    # print(type(encryptedMsg[3]))
    encryptedMsgObj = {
        'ciphertext': binascii.hexlify(encryptedMsg[0]),
        'nonce': binascii.hexlify(encryptedMsg[1]),
        'authTag': binascii.hexlify(encryptedMsg[2]),
        'ciphertextPubKey': hex(encryptedMsg[3].x) + hex(encryptedMsg[3].y % 2)[2:]
    }

    # new_encryptedMsgObj = {
    #     'ciphertext': binascii.b2a_hex(encryptedMsg[0]),
    #     'nonce': binascii.b2a_hex(encryptedMsg[1]),
    #     'authTag': binascii.b2a_hex(encryptedMsg[2]),
    #     'ciphertextPubKey': hex(encryptedMsg[3].x) + hex(encryptedMsg[3].y % 2)[2:]
    # }

    print('encryptedMsgObj', encryptedMsgObj)
    print("---------------------------------")

    key_list = encryptedMsgObj.keys()
    val_list = encryptedMsgObj.values()
    val_list = [i.decode() if idx != 3 else i for idx, i in enumerate(val_list)]

    key_str = ' '.join(key_list)
    val_str = ' '.join(val_list)
    final_string = key_str + '-' + val_str
    return final_string


def decrypt_AES_GCM(ciphertext, nonce, authTag, secretKey):
    aesCipher = AES.new(secretKey, AES.MODE_GCM, nonce)
    plaintext = aesCipher.decrypt_and_verify(ciphertext, authTag)
    return plaintext


def decrypt_ECC(encrypted_msg, p2_key):
    (ciphertext, nonce, authTag, ciphertextPubKey) = encrypted_msg.values()
    print("encrypted_msg", encrypted_msg)
    print('p2_key', p2_key)
    print('ciphertextPubKey', ciphertextPubKey)

    print("ciphertext", ciphertext)
    print('nonce', nonce)
    print('authTag', authTag)
    sharedECCKey = p2_key * ciphertextPubKey
    secretKey = ecc_point_to_256_bit_key(sharedECCKey)
    plaintext = decrypt_AES_GCM(ciphertext, nonce, authTag, secretKey)
    return plaintext


def decryption(enc_text, p1_key):
    enc_text = enc_text.split('-')
    k_list = enc_text[0].split(' ')
    v_list = enc_text[1].split(' ')
    v_list = [i.encode() if idx != 3 else i for idx, i in enumerate(v_list)]
    encryptedMsg = {k: v for (k, v) in zip(k_list, v_list)}
    print("encryptedMsg", encryptedMsg)
    print(type(encryptedMsg))
    print("---------------------------------")
    last = encryptedMsg['ciphertextPubKey']
    print("last", last)
    last = last[2:]
    print("last", last)
    print("---------------------------------")
    last = int(last, 16)
    skBytes = bytes.fromhex(str(last))
    print("skBytes", skBytes)
    s = int.from_bytes(skBytes, 'big', signed=False)
    print("s", s)
    # privateKey = ECC.construct(curve="brainpoolP384r1", d=s)
    privateKey = ECC.construct(curve="brainpoolP256r1", d=s)
    # privateKey = ECC.construct(curve='brainpoolP512r1', d=s)

    print("privateKey", privateKey)
    print("---------------------------------")

    # new_encryptedMsgObj = {
    #     'ciphertext': binascii.b2a_hex(encryptedMsg[0]),
    #     'nonce': binascii.b2a_hex(encryptedMsg[1]),
    #     'authTag': binascii.b2a_hex(encryptedMsg[2]),
    #     'ciphertextPubKey': hex(encryptedMsg[3].x) + hex(encryptedMsg[3].y % 2)[2:]
    # }

    new_encryptedMsgObj = {'ciphertext': binascii.unhexlify(v_list[0]), 'nonce': binascii.unhexlify(v_list[1]),
                           'authTag': binascii.unhexlify(v_list[2]), 'ciphertextPubKey': s}
    #
    # print('New_encryptedMsgObj', new_encryptedMsgObj)
    # decrypted_text = 'hlo'
    # decrypted_text = decrypt_ECC(encryptedMsg, p1_key)
    decrypted_text = decrypt_ECC(new_encryptedMsgObj, p1_key)
    return decrypted_text


keys = generate_keys()
pri_key = keys[0]
pub_key = keys[1]

text = input("Enter text for encryption: ")
encrypted = encryption(text, pub_key)

# print("-----------------")
# print(encrypted)
# print(pri_key)
# print(type(pri_key))

decrypted = decryption(encrypted, pri_key)
print("Decrypted", decrypted)
