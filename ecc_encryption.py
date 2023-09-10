import hashlib
import secrets
from Crypto.Cipher import AES
from tinyec import registry
import pickle as pkl
from hashlib import md5
from os import urandom
import random

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
    pubKey = int(pubKey) * curve.g
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
    (ciphertext, nonce, authTag, ciphertextPubKey) = encrypted_msg
    sharedECCKey = int(p2_key) * ciphertextPubKey
    secretKey = ecc_point_to_256_bit_key(sharedECCKey)
    plaintext = decrypt_AES_GCM(ciphertext, nonce, authTag, secretKey)
    return plaintext


def derive_key_and_iv(password, salt, key_length, iv_length):  # derive key and IV from password and salt.
    d = d_i = b''
    while len(d) < key_length + iv_length:
        d_i = md5(d_i + str.encode(password) + salt).digest()  # obtain the md5 hash value
        d += d_i
    return d[:key_length], d[key_length:key_length + iv_length]


def ecc_encryption(in_file, out_file, public_key, p_file_name, key_length=32):
    pickle_file_name = p_file_name.split('.')[0] + '.pkl'
    bs = AES.block_size  # 16 bytes
    salt = urandom(bs)  # return a string of random bytes
    password = str(random.randint(1000, 10000))
    key, iv = derive_key_and_iv(password, salt, key_length, bs)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    out_file.write(salt)
    finished = False

    while not finished:
        chunk = in_file.read(1024 * bs)
        if len(chunk) == 0 or len(chunk) % bs != 0:  # final block/chunk is padded before encryption
            padding_length = (bs - len(chunk) % bs) or bs
            chunk += str.encode(padding_length * chr(padding_length))
            finished = True
        out_file.write(cipher.encrypt(chunk))
    encrypted = encrypt_ECC(password, public_key)
    file_path = "static/pickle_files/" + pickle_file_name
    with open(file=file_path, mode="wb") as file:
        pkl.dump(obj=encrypted, file=file)
    return file_path


def ecc_decryption(in_file, out_file, pkl_filename, private_key, key_length=32):
    pickle_file_name = pkl_filename.split('.')[0] + '.pkl'
    pickle_file_location = 'static/pickle_files/' + pickle_file_name
    with open(file=pickle_file_location, mode="rb") as file:
        res_msg = pkl.load(file=file)

    dec_text = decrypt_ECC(res_msg, private_key)
    dec_text = dec_text.decode()
    bs = AES.block_size
    salt = in_file.read(bs)
    key, iv = derive_key_and_iv(str(dec_text), salt, key_length, bs)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    next_chunk = ''
    finished = False
    while not finished:
        chunk, next_chunk = next_chunk, cipher.decrypt(in_file.read(1024 * bs))
        if len(next_chunk) == 0:
            padding_length = chunk[-1]
            chunk = chunk[:-padding_length]
            finished = True
        out_file.write(bytes(x for x in chunk))




