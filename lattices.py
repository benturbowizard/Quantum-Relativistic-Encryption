import pqcrypto as pq
import math
import os
import hashlib
import numpy as np
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import ciphers

# Updated encode function to handle string encoding
def encode(message, K):
    print("Debug: Inside encode function.")
    if isinstance(message, str):
        message_bytes = message.encode('utf-8')
        binary_message = ''.join(format(byte, '08b') for byte in message_bytes)
        padded_message = binary_message.ljust(K, '0')
        return padded_message[:K]
    else:
        raise ValueError("Message must be a string.")

# Placeholder for generate_gadget_matrix
def generate_gadget_matrix(n, nB):
    print("Debug: Inside generate_gadget_matrix function.")
    gadget_matrix = np.random.rand(n, nB)
    return gadget_matrix

def save_key(key, filename):
    print("Debug: Inside save_key function.")
    with open(filename, 'wb') as f:
        f.write(key)

def load_key(filename):
    print("Debug: Inside load_key function.")
    if os.path.exists(filename):
        with open(filename, 'rb') as f:
            return f.read()
    else:
        return None

# Discrete Gaussian sampler
def gaussian_sampler(mu, sigma, n, q):
    print("Debug: Inside gaussian_sampler function.")
    samples = np.random.normal(mu, sigma, n)
    return [int(round(s)) % q for s in samples]

# Lattice key generation
def generate_key_pair(n, q):
    print("Debug: Inside generate_key_pair function.")
    print(f"Debug: Parameters - n: {n}, q: {q}")
    priv_key = gaussian_sampler(0, 8, n, q)
    print(f"Debug: Private key length: {len(priv_key)}")
    B = 64  
    gadget_matrix = generate_gadget_matrix(n, n*B)
    pub_key = priv_key @ gadget_matrix
    print("Debug: Public key generated.")
    return priv_key, pub_key

# Regev encryption
def encrypt(pub_key, message, n, q):
    print("Debug: Inside encrypt function.")
    print(f"Debug: Parameters - pub_key shape: {np.shape(pub_key)}, message: {message}, n: {n}, q: {q}")
    K = 16
    u = encode(message, K)
    e1 = gaussian_sampler(0, 8, n, q)
    e2 = gaussian_sampler(0, 8, K, q)
    u = [int(bit) for bit in u]
    e1 = [int(e) for e in e1]
    e2 = [int(e) for e in e2]
    c0 = np.matmul(pub_key.reshape(-1, n), e1)
    c0 = [(c + u_i) % q for c, u_i in zip(c0, u)]
    c1 = e2
    return c0, c1

# Regev decryption
def decrypt(priv_key, c0, c1):
    print("Debug: Inside decrypt function.")
    v = priv_key @ c0
    return pq.decode(v - c1)

# Key derivation  
def derive_key(seed):
    print("Debug: Inside derive_key function.")
    return hashlib.sha256(seed).digest()

# AES-256-GCM encryption
def aes_encrypt(key, plaintext):
    print("Debug: Inside aes_encrypt function.")
    aes_cipher = AESCipher(key)
    return aes_cipher.encrypt(plaintext)

# AES-256-GCM decryption  
def aes_decrypt(key, ciphertext):
    print("Debug: Inside aes_decrypt function.")
    aes_cipher = AESCipher(key)
    return aes_cipher.decrypt(ciphertext)

# Hybrid Encryptor class
class Encryptor:
    def __init__(self, public_key):
        print("Debug: Inside Encryptor constructor.")
        self.pub_key = public_key
  
    def encrypt(self, message, n, q):
        print("Debug: Inside Encryptor encrypt function.")
        c1, c2 = encrypt(self.pub_key, message, n, q)  
        seed = os.urandom(32)
        c1_bytes = np.array(c1, dtype=np.uint8).tobytes()
        c2_bytes = np.array(c2, dtype=np.uint8).tobytes()
        key = derive_key(seed + c1_bytes + c2_bytes)
        if isinstance(message, str):
            message = message.encode('utf-8')
        ciphertext, tag = aes_encrypt(key, message)
        try:
            # ... (existing code)
            print(f"Debug: About to return values. c1: {c1}, c2: {c2}, ciphertext: {ciphertext}, tag: {tag}, seed: {seed}")  # New Debugging Line
            return c1, c2, ciphertext, tag, seed
        except Exception as e:
            print(f"Debug: Encryption failed inside Encryptor class: {e}")
            return None

# Hybrid Decryptor class  
class Decryptor:
    def __init__(self, private_key):
        print("Debug: Inside Decryptor constructor.")
        self.priv_key = private_key

    def decrypt(self, c1, c2, ciphertext, tag, seed):
        print("Debug: Inside Decryptor decrypt function.")
        message = decrypt(self.priv_key, c1, c2)
        key = derive_key(seed + c1 + c2)
        plaintext = aes_decrypt(key, ciphertext, tag)
        return plaintext

class AESCipher:
    def __init__(self, key):
        print("Debug: Inside AESCipher constructor.")
        print(f"Debug: Key: {key}")  # New Debugging Line
        self.key = key

    def encrypt(self, plaintext):
        print("Debug: Inside AESCipher encrypt function.")
        print(f"Debug: Plaintext: {plaintext}")  # New Debugging Line
        iv = os.urandom(12)
        cipher = Cipher(algorithms.AES(self.key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return (iv, ciphertext, encryptor.tag)

    def decrypt(self, iv, ciphertext, tag):
        print("Debug: Inside AESCipher decrypt function.")
        cipher = Cipher(algorithms.AES(self.key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()
