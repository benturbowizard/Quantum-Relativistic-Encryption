import socket
import time
import pickle
from lattices import encode, generate_key_pair, Encryptor, Decryptor

N = 256
q = 4093

print('Generating client keys...')
t1 = time.time()
private_key, public_key = generate_key_pair(N, q)
t2 = time.time()
print(f'Keygen took {t2 - t1:.2f} seconds')

print('Connecting to server...')

HOST = 'localhost'
PORT = 12345

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))

    print('Encrypting...')
    t1 = time.time()
    encryptor = Encryptor(public_key)
    try:
        c1, c2, ciphertext, tag, seed = encryptor.encrypt("Message", N, q)
    except Exception as e:
        print(f"Encryption failed: {e}")
        exit(1)
    t2 = time.time()
    print(f'Encryption took {t2 - t1:.2f} seconds')

    # Serialize and send data
    try:
        # Explicitly cast c1, c2, and seed to bytes
        c1_bytes = c1.astype(np.uint8).tobytes()
        c2_bytes = c2.astype(np.uint8).tobytes()
        seed_bytes = seed.astype(np.uint8).tobytes()

        serialized_data = pickle.dumps([c1_bytes, c2_bytes, ciphertext, tag, seed_bytes])
    except Exception as e:
        print(f"Serialization failed: {e}")
        exit(1)

    print(f"Serialized data to send: {serialized_data}")
    s.send(serialized_data)

    # Receive and deserialize data
    received_data = s.recv(1024)
    c1_bytes, c2_bytes, ciphertext, tag, seed_bytes = pickle.loads(received_data)

    # Convert bytes back to NumPy arrays
    c1 = np.frombuffer(c1_bytes, dtype=np.int64)
    c2 = np.frombuffer(c2_bytes, dtype=np.int64)
    seed = np.frombuffer(seed_bytes, dtype=np.uint8)

    print('Decrypting...')
    t1 = time.time()
    decryptor = Decryptor(private_key)
    plaintext = decryptor.decrypt(c1, c2, ciphertext, tag, seed)
    t2 = time.time()
    print(f'Decryption took {t2 - t1:.2f} seconds')
