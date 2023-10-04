import socket
import time
import pickle
from lattices import generate_key_pair, Encryptor, Decryptor, encode

N = 256
q = 4093

message = "Hello World"

print('Generating client keys...')
t1 = time.time()
private_key, public_key = generate_key_pair(N, q)
t2 = time.time()
print(f'Keygen took {t2 - t1:.2f} seconds')
print(f'Shape of public_key after generation: {public_key.shape}')

print('Connecting to server...')
HOST = 'localhost'
PORT = 12345

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))

    print('Encrypting...')
    t1 = time.time()
    # Initialize the Encryptor class
    encryptor = Encryptor(public_key, N, q)

    # Try to encrypt the message
    try:
        print("Debug: Inside Encryptor constructor.")  # Existing Debugging Line
        print("Debug: About to call encrypt function.")  # Existing Debugging Line
        print(f"Debug: Message to encrypt: {message}")  # Existing Debugging Line
    
        # Store the result of the encrypt function in a variable first
        encryption_result = encryptor.encrypt(message, N, q)
    
        # New Debugging Line: Print what the encrypt function returned
        print(f"Debug: Encryption result: {encryption_result}")
        print("Debug: About to unpack values.")

        print("Debug: About to unpack values.")
        # Then unpack the result into variables
        c1, c2, ciphertext, tag, seed = encryption_result
        print("Debug: Unpacked values successfully.")
        print(f"Debug: c1: {c1}, c2: {c2}, ciphertext: {ciphertext}, tag: {tag}, seed: {seed}")  # New Debugging Line
        print("Debug: Encryption successful.")
    except Exception as e:
        print(f"Debug: Exception details: {e}")
        print(f"Encryption failed: {e}")
        exit(1)
    t2 = time.time()
    print(f'Encryption took {t2 - t1:.2f} seconds')

    # Serialize and send data
    try:
        print("Debug: About to serialize data.")
        c1_list = c1
        c2_list = c2
        seed_list = seed
        print(f"Debug: Serialized lists: c1_list: {c1_list}, c2_list: {c2_list}, seed_list: {seed_list}")

        serialized_data = pickle.dumps([c1_list, c2_list, ciphertext, tag, seed_list])
    except Exception as e:
        print(f"Debug: Exception details: {e}")
        print(f"Serialization failed: {e}")
        exit(1)

    print(f"Serialized data to send: {serialized_data}")
    s.send(serialized_data)

    # Receive data
    recv_data = s.recv(1024) 
    print("Received data:", recv_data) # Added print

    while True:
        data = s.recv(1024)
        if not data:
            break
        c1, c2, ciphertext, tag, seed = pickle.loads(recv_data)
        print(f"Debug: Received data: {received_data}")

        print('Decrypting...')
        t1 = time.time()
        decryptor = Decryptor(private_key)
        plaintext = decryptor.decrypt(c1, c2, ciphertext, tag, seed)
        t2 = time.time()
        print(f'Decryption took {t2 - t1:.2f} seconds')
