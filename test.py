#import os
import base64
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend


backend=default_backend()
#Salt should be generated randomly
salt=open("salt.txt","rb").read()
#print(salt)
#derive
kdf= Scrypt(
    salt=salt,
    length=32,
    n=2**14,
    r=8,
    p=1,
    backend=backend
)

key=kdf.derive(b"the pass word")

newkey=base64.urlsafe_b64encode(key)

with open("derivedKey.key","wb") as deKey:
    deKey.write(newkey)

#print(key)
#verify
kdf= Scrypt(
    salt=salt,
    length=32,
    n=2**14,
    r=8,
    p=1,
    backend=backend
)

kdf.verify(b"the pass word",key)


