# lattices.py 

import pqcrypto as pq
import math
import os
import hashlib
import numpy as np

# Placeholder for generate_gadget_matrix
def generate_gadget_matrix(n, nB):
    # TODO: Implement the actual function
    print("Placeholder for generate_gadget_matrix called with n =", n, "and nB =", nB)
    return None  # Replace with actual return value


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
  pub_key = priv_key @ generate_gadget_matrix(n, n*B)

  return priv_key, pub_key

# Regev encryption
def encrypt(pub_key, message):
  
  # Encode message
  K = 16
  u = pq.encode(message, K)

  # Sample error vectors   
  e1 = gaussian_sampler(0, 8, n, q)
  e2 = gaussian_sampler(0, 8, K, q)

  # Compute ciphertext
  c0 = pub_key @ e1 + u
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
  return hashlib.kmac(seed).digest(32)

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
  
  def encrypt(self, message):
    # Regev encrypt
    c1, c2 = encrypt(self.pub_key, message)  

    # Derive AES key
    seed = os.urandom(32)
    key = derive_key(seed + c1 + c2)

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