import hashlib


def file_checksum(data):
    # Checksum of uploaded bytes for de-duplication.
    return hashlib.md5(data).hexdigest()
