import os
salt=os.urandom(16)
with open("salt.txt","wb") as salt_file:
    salt_file.write(salt)