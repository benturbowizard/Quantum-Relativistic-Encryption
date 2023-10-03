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
    if isinstance(message, str):
        # Encode the message as bytes using UTF-8 encoding
        message_bytes = message.encode('utf-8')
        binary_message = ''.join(format(byte, '08b') for byte in message_bytes)
        padded_message = binary_message.ljust(K, '0')
        return padded_message[:K]
    else:
        raise ValueError("Message must be a string.")

# Placeholder for generate_gadget_matrix
def generate_gadget_matrix(n, nB):
    # Generate a random matrix with values between 0 and 1
    gadget_matrix = np.random.rand(n, nB)
    
    return gadget_matrix

def save_key(key, filename):
    with open(filename, 'wb') as f:
        f.write(key)

def load_key(filename):
    if os.path.exists(filename):
        with open(filename, 'rb') as f:
            return f.read()
    else:
        return None

# Discrete Gaussian sampler
def gaussian_sampler(mu, sigma, n, q):
  samples = np.random.normal(mu, sigma, n)
  return [int(round(s)) % q for s in samples]

# Lattice key generation
def generate_key_pair(n, q):
  # Sample from discrete Gaussian
  priv_key = gaussian_sampler(0, 8, n, q)
  
  # Compute public key 
  B = 64  
  gadget_matrix = generate_gadget_matrix(n, n*B)
  
  # Debugging: Print the shapes
  print("Shape of gadget_matrix:", np.shape(gadget_matrix))
  print("Length of priv_key:", len(priv_key))

  pub_key = priv_key @ gadget_matrix

  # More Debugging: Print the shape of pub_key
  print("Shape of pub_key after generation:", np.shape(pub_key))

  return priv_key, pub_key

# Regev encryption
def encrypt(pub_key, message, n, q):
    # Encode message
    K = 16
    u = encode(message, K)

    # Sample error vectors   
    e1 = gaussian_sampler(0, 8, n, q)
    e2 = gaussian_sampler(0, 8, K, q)

    # Ensure data types are consistent
    u = [int(bit) for bit in u]
    e1 = [int(e) for e in e1]
    e2 = [int(e) for e in e2]

    # Debugging: Print the shapes and data types
    print("Shape of pub_key:", np.shape(pub_key))
    print("Length of e1:", len(e1))
    print("Data type of e1[0]:", type(e1[0]))
    print("Data type of u[0]:", type(u[0]))

    # Compute ciphertext
    try:
        c0 = np.matmul(pub_key.reshape(-1, n), e1)
        c0 = [(c + u_i) % q for c, u_i in zip(c0, u)]
    except ValueError as e:
        print("Matrix multiplication failed:", e)
        return None
    c1 = e2

    return c0, c1

# Regev decryption
def decrypt(priv_key, c0, c1):

  # Compute v  
  v = priv_key @ c0

  # Decode message
  return pq.decode(v - c1)

# Key derivation  
def derive_key(seed):
    return hashlib.sha256(seed).digest()

# AES-256-GCM encryption
def aes_encrypt(key, plaintext):
  aes_cipher = AESCipher(key)
  return aes_cipher.encrypt(plaintext)

# AES-256-GCM decryption  
def aes_decrypt(key, ciphertext):
  aes_cipher = AESCipher(key)
  return aes_cipher.decrypt(ciphertext)

# Hybrid Encryptor class
class Encryptor:

  def __init__(self, public_key):
    self.pub_key = public_key
  
  def encrypt(self, message, n, q):
    # Regev encrypt
    c1, c2 = encrypt(self.pub_key, message, n, q)  

    # Derive AES key
    seed = os.urandom(32)
    # Convert c1 and c2 to NumPy arrays and then to bytes before concatenating
    c1_bytes = np.array(c1, dtype=np.uint8).tobytes()
    c2_bytes = np.array(c2, dtype=np.uint8).tobytes()
    key = derive_key(seed + c1_bytes + c2_bytes)

    # Encode message if string
    if isinstance(message, str):
        message = message.encode('utf-8')

    # AES encrypt 
    ciphertext, tag = aes_encrypt(key, message)

    return c1, c2, ciphertext, tag, seed

# Hybrid Decryptor class  
class Decryptor:

  def __init__(self, private_key):
    self.priv_key = private_key

  def decrypt(self, c1, c2, ciphertext, tag, seed):
   
    # Regev decrypt 
    message = decrypt(self.priv_key, c1, c2)

    # Derive AES key
    key = derive_key(seed + c1 + c2)

    # AES decrypt
    plaintext = aes_decrypt(key, ciphertext, tag)

    return plaintext

class AESCipher:
    def __init__(self, key):
        self.key = key

    def encrypt(self, plaintext):
        iv = os.urandom(12)
        encryptor = Cipher(
            algorithms.AES(self.key),
            modes.GCM(iv),
            backend=default_backend()
        ).encryptor()

        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        tag = encryptor.tag
        return (iv, ciphertext, tag)

    def decrypt(self, iv, ciphertext, tag):
        decryptor = Cipher(
            algorithms.AES(self.key),
            modes.GCM(iv, tag),
            backend=default_backend()
        ).decryptor()

        return decryptor.update(ciphertext) + decryptor.finalize()