import socket
import time
from lattices import load_key, generate_key_pair, Encryptor, Decryptor

# Lattice params  
N = 256 
q = 4093

print('Generating server keys...')
t1 = time.time()
private_key, public_key = generate_key_pair(N, q)
t2 = time.time()
print(f'Keygen took {t2-t1:.2f} seconds')

print('Starting server...')

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:

  # Socket server setup

  while True:
    data = conn.recv(1024)

    print('Decrypting...') 
    t1 = time.time()
    decryptor = Decryptor(private_key)
    plaintext = decryptor.decrypt(ciphertext)
    t2 = time.time()
    print(f'Decryption took {t2-t1:.2f} seconds')

    # Encryption 
    print('Encrypting...')
    t1 = time.time()
    encryptor = Encryptor(public_key) 
    ciphertext = encryptor.encrypt(plaintext)
    t2 = time.time()
    print(f'Encryption took {t2-t1:.2f} seconds')

    conn.send(ciphertext)