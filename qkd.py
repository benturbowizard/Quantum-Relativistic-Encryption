import quantropy as qp

def generate_key():

    alice = qp.Alice()
    bob = qp.Bob()

    alice.prepare_BB84_states(n=100)

    alice.send(bob)
    bob.receive(alice)

    key = bob.sift_key()

    return key