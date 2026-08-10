import os


def make_world_writable(path):
    os.chmod(path, 0o777)
