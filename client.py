import socket 
import time
import pickle  # For data serialization
from lattices import encode, generate_key_pair, load_key, Encryptor, Decryptor

N = 256
q = 4093

print('Generating client keys...')
t1 = time.time()
private_key, public_key = generate_key_pair(N, q)  
t2 = time.time()
print(f'Keygen took {t2-t1:.2f} seconds')

print('Connecting to server...')

HOST = 'localhost'
PORT = 12345

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    
    print('Encrypting...')
    t1 = time.time()
    encryptor = Encryptor(public_key)
    c1, c2, ciphertext, tag, seed = encryptor.encrypt(encode(b'Message', 16), N, q)
    t2 = time.time()
    print(f'Encryption took {t2-t1:.2f} seconds')

    # Serialize and send data
    s.send(pickle.dumps([c1, c2, ciphertext, tag, seed]))
    
    # Receive and deserialize data
    received_data = s.recv(1024)
    c1, c2, ciphertext, tag, seed = pickle.loads(received_data)

    print('Decrypting...')
    t1 = time.time()
    decryptor = Decryptor(private_key)
    plaintext = decryptor.decrypt(c1, c2, ciphertext, tag, seed)
    t2 = time.time()
    print(f'Decryption took {t2-t1:.2f} seconds')
