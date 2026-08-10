import pickle


def load_session(raw_bytes):
    return pickle.loads(raw_bytes)
