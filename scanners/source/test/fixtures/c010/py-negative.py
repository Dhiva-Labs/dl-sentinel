import os


def fix_permissions(path):
    os.chmod(path, 0o644)
