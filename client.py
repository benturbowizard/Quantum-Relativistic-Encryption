import socket
import time
import pickle
from lattices import generate_key_pair, Encryptor, Decryptor, encode

N = 256
q = 4093

print('Generating client keys...')
t1 = time.time()
private_key, public_key = generate_key_pair(N, q)
t2 = time.time()
print(f'Keygen took {t2 - t1:.2f} seconds')
print(f'Shape of pub_key after generation: {public_key.shape}')

print('Connecting to server...')
HOST = 'localhost'
PORT = 12345

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))

    print('Encrypting...')
    t1 = time.time()
    encryptor = Encryptor(public_key)
    try:
        print("Debug: About to call encrypt function.")
        message = "Message"
        c1, c2, ciphertext, tag, seed = encryptor.encrypt(message, N, q)
        print("Debug: Encryption successful.")
    except Exception as e:
        print(f"Encryption failed: {e}")
        exit(1)
    t2 = time.time()
    print(f'Encryption took {t2 - t1:.2f} seconds')

    # Serialize and send data
    try:
        print("Debug: About to serialize data.")
        c1_list = c1.tolist()
        c2_list = c2.tolist()
        seed_list = seed.tolist()

        serialized_data = pickle.dumps([c1_list, c2_list, ciphertext, tag, seed_list])
    except Exception as e:
        print(f"Serialization failed: {e}")
        exit(1)

    print(f"Serialized data to send: {serialized_data}")
    s.send(serialized_data)

    # Receive and deserialize data
    received_data = s.recv(1024)
    c1_list, c2_list, ciphertext, tag, seed_list = pickle.loads(received_data)

    # Convert lists back to NumPy arrays
    c1 = c1_list
    c2 = c2_list
    seed = seed_list

    print('Decrypting...')
    t1 = time.time()
    decryptor = Decryptor(private_key)
    plaintext = decryptor.decrypt(c1, c2, ciphertext, tag, seed)
    t2 = time.time()
    print(f'Decryption took {t2 - t1:.2f} seconds')
