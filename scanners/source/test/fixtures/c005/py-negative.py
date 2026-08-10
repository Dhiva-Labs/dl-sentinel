import os

SAFE_DIR = '/data/uploads'


def read_upload(filename):
    return open(os.path.join(SAFE_DIR, os.path.basename(filename)), 'r')


def read_fixed():
    return open(os.path.join(SAFE_DIR, 'manifest.json'), 'r')
