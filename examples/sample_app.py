import hashlib


MODE = "AES-128-CBC"
digest = hashlib.md5(b"x").hexdigest()
