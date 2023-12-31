import socket
import time
import pickle
from lattices import generate_key_pair, Encryptor, Decryptor

# Lattice params  
N = 256 
q = 4093

print('Generating server keys...')
t1 = time.time()
private_key, public_key = generate_key_pair(N, q)
t2 = time.time()
print(f'Keygen took {t2 - t1:.2f} seconds')

# Add Debugging Step
print("Debug: Server keys generated successfully.")
print('Debug: Parameters - N:', N, ', q:', q)  # New Debugging Line


print('Starting server...')
HOST = 'localhost'
PORT = 12345
print("Debug: About to start the server.")

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    conn, addr = s.accept()
    with conn:
        print('Connected by', addr)
        
        # Receive and deserialize data
        received_data = conn.recv(1024)
        print(f"Debug: Received data length: {len(received_data)}")
        print(f"Received serialized data: {received_data}")  # Debugging line
        if received_data:
            print("Debug: About to deserialize data.")
            c1, c2, ciphertext, tag, seed = pickle.loads(received_data)
            
            print('Decrypting...') 
            t1 = time.time()
            decryptor = Decryptor(private_key)
            plaintext = decryptor.decrypt(c1, c2, ciphertext, tag, seed)
            t2 = time.time()
            print(f'Decryption took {t2 - t1:.2f} seconds')

            print('Encrypting...')
            t1 = time.time()
            encryptor = Encryptor(public_key) 
            c1, c2, ciphertext, tag, seed = encryptor.encrypt(message, N, q)
            t2 = time.time()
            print(f'Encryption took {t2 - t1:.2f} seconds')

            print("Debug: About to serialize data.")
            # Serialize data 
            serialized_data = pickle.dumps([c1, c2, ciphertext, tag, seed])

            print("Serialized data:", serialized_data)
            print("Serialized data length:", len(serialized_data))

            bytes_sent = conn.send(serialized_data)  
            print("Bytes sent:", bytes_sent)
            
        else:
            print("No data received.")
