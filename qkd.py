import quantropy as qp

def generate_key():
    alice = qp.Alice()
    bob = qp.Bob()
    print("Debug: Alice and Bob objects created.")
    alice.prepare_BB84_states(n=100)
    print("Debug: BB84 states prepared.")
    alice.send(bob)
    bob.receive(alice)
    print("Debug: Key exchange completed.")
    key = bob.sift_key()
    return key
