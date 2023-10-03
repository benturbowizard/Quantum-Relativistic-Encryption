# lattices.py 

import pqcrypto as pq
import math
import os
import hashlib
import numpy as np

# Implement the placeholder function for encoding the message
def encode(message, K):
    if isinstance(message, bytes):
        message = message.decode('utf-8')
    binary_message = ''.join(format(ord(char), '08b') for char in message)
    padded_message = binary_message.ljust(K, '0')
    return padded_message[:K]

# Placeholder for generate_gadget_matrix
def generate_gadget_matrix(n, nB):
    # TODO: Implement the actual function
    print("Placeholder for generate_gadget_matrix called with n =", n, "and nB =", nB)
    
    # Return a mock matrix filled with zeros (or any other mock data)
    return np.zeros((n, nB))


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

  # Compute ciphertext
  # Debugging: Print the shapes
  print("Shape of pub_key:", np.shape(pub_key))
  print("Length of e1:", len(e1))

  # Compute ciphertext
  try:
    c0 = pub_key @ e1 + u
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
  
  def encrypt(self, message, n, q):
    # Regev encrypt
    c1, c2 = encrypt(self.pub_key, message, n, q)  

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