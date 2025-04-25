import os
import hashlib
import time

def generate_file_hash(path):
    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hasher.update(chunk)
    return hasher.hexdigest()

def cleanup_temp_files(directory, max_age_seconds=600):
    now = time.time()
    for filename in os.listdir(directory):
        path = os.path.join(directory, filename)
        if os.path.isfile(path) and now - os.path.getmtime(path) > max_age_seconds:
            os.remove(path)
