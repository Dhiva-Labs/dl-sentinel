import hashlib


def hash_password(password):
    # Insecure: MD5 used to hash a password.
    return hashlib.md5(password.encode("utf-8")).hexdigest()
