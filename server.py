import socket
import time
from lattices import encode, load_key, generate_key_pair, Encryptor, Decryptor
import pickle  # For data serialization

# Lattice params  
N = 256 
q = 4093

print('Generating server keys...')
t1 = time.time()
private_key, public_key = generate_key_pair(N, q)
t2 = time.time()
print(f'Keygen took {t2-t1:.2f} seconds')

print('Starting server...')

HOST = 'localhost'
PORT = 12345

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    conn, addr = s.accept()
    with conn:
        print('Connected by', addr)
        
        # Receive and deserialize data
        received_data = conn.recv(1024)
        print("Received data:", received_data)  # Debugging line
        if received_data:
            c1, c2, ciphertext, tag, seed = pickle.loads(received_data)
            
            print('Decrypting...') 
            t1 = time.time()
            decryptor = Decryptor(private_key)
            plaintext = decryptor.decrypt(c1, c2, ciphertext, tag, seed)
            t2 = time.time()
            print(f'Decryption took {t2-t1:.2f} seconds')

            print('Encrypting...')
            t1 = time.time()
            encryptor = Encryptor(public_key) 
            c1, c2, ciphertext, tag, seed = encryptor.encrypt(plaintext)
            t2 = time.time()
            print(f'Encryption took {t2-t1:.2f} seconds')

            # Serialize and send data
            conn.send(pickle.dumps([c1, c2, ciphertext, tag, seed]))
        else:
            print("No data received.")
