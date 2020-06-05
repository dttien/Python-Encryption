from tkinter import filedialog
from cryptography.fernet import Fernet
from tkinter import *
import tkinter as tk
import base64
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
import os
backend=default_backend()
def pass2key(password):
    salt = open("salt.txt", "rb").read()
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2 ** 14,
        r=8,
        p=1,
        backend=backend
    )
    key= kdf.derive(password.encode('utf-8'))
    return base64.urlsafe_b64encode(key)

root=Tk()

filename="global"
keyname="global"
keypath="global"
keyInUse='keyInUse'




def write_key(keyname):
    keydir= keyname+".key"
    key= Fernet.generate_key()
    with open(keydir,"wb") as key_file:
        key_file.write(key)
def load_key(keyname):

    return open(keyname,"rb").read()
    #return file


"""
manualkey= input("Please enter key: ")
encodekey=base64.b64encode(manualkey.encode('ascii'))
print(manualkey)

write_key()
key= load_key()
message="bruh".encode()
f=Fernet(key)
encrypted=f.encrypt(message)
print(encrypted)
decrypted=f.decrypt(encrypted)
print(decrypted)
"""


def encypt(filename,key):
    f=Fernet(key)
    with open(filename,"rb") as file:
        file_data=file.read()
    encrypted_data=f.encrypt(file_data)
    newname='Encrypted'
    name,ext=os.path.splitext(filename)
    with open(newname+ext,"wb") as file:
        file.write(encrypted_data)
def decrypt(filename,key):
    f=Fernet(key)
    with open(filename,"rb") as file:
        encrypted_data=file.read()
    decrypted_data = f.decrypt(encrypted_data)
    newname = 'Decrypted'
    name, ext = os.path.splitext(filename)
    with open(newname+ext,"wb") as file:
        file.write(decrypted_data)

#write_key("fuckU")


#decrypt(root.fileName,key)


def encryptfunc():
    global filename
    #global keypath
    #key = load_key(keypath)

    encypt(filename, keyInUse)

def decrypfunc():
    global filename
    #global  keypath
    #print(keypath)
    #key=load_key(keypath)



    decrypt(filename,keyInUse)

def openfiledialog():
    global filename
    filename = filedialog.askopenfilename()
def openkeydialog():
    global keypath
    global keyInUse
    keypath=filedialog.askopenfilename(filetypes=[('Key file','*.key')])
    keyInUse=load_key(keypath)



def openpassword():
    global password
    global keyInUse
    keyInUse=pass2key(filedialog.askopenfilename(filetypes=[('Text file','*.txt')]))
    #print(keyInUse)




def encryptWindow():
    newWindow = tk.Toplevel(root)

    bottom=Frame(newWindow)
    bottom.pack(side=BOTTOM,fill=BOTH,expand=True)

    def on_close():
        newWindow.destroy()
        root.deiconify()

    def makenewkey():
        global  keyname
        newWindow.withdraw()
        subWind=tk.Toplevel(newWindow)



        text=tk.Text(subWind,width=30,height=2)
        text.pack()
        text.insert(tk.END,"Enter key name")
        v=StringVar()
        entry=Entry(subWind,textvariable=v)
        entry.pack()



        def create():
            keyname = v.get()
            write_key(keyname)
            newWindow.deiconify()
            subWind.destroy()

        create=Button(subWind,text="GENERATE",command=create)
        create.pack()



    def disablekey():
        usekey['state'] = DISABLED

    def disablepassword():
        usepass['state']=DISABLED

    root.withdraw()
    canvas1=tk.Canvas(newWindow,width=200,height=30)
    canvas1.pack()
    choosefile =tk.Button(newWindow,text="Browse file",command =openfiledialog)
    choosefile.pack()

    newkey=tk.Button(newWindow,text="New key",command=makenewkey)
    newkey.pack()

    usekey=tk.Button(newWindow,text="Use existed key",command= lambda :[openkeydialog(),disablepassword()])
    usekey.pack(side=tk.LEFT)

    usepass=tk.Button(newWindow, text="Use password",command=lambda :[openpassword(),disablekey()])
    usepass.pack(side=tk.RIGHT)

    encrButton=tk.Button(newWindow,text="ENCRYPT NOW", command=encryptfunc)
    encrButton.pack(in_=bottom)





    newWindow.protocol("WM_DELETE_WINDOW",on_close)




def decryptWindow():
    newWindow=tk.Toplevel(root)
    bottom = Frame(newWindow)
    bottom.pack(side=BOTTOM, fill=BOTH, expand=True)


    def on_close():
        newWindow.destroy()
        root.deiconify()

    def disablekey():
        keyButton['state'] = DISABLED

    def disablepassword():
        usepass['state'] = DISABLED



    root.withdraw()

    canvas1=tk.Canvas(newWindow,width=200,height=100)
    canvas1.pack()
    choosefile =tk.Button(newWindow,text="Browse file",command =openfiledialog)
    choosefile.pack()
    keyButton = tk.Button(newWindow, text="Browse key", command=lambda:[openkeydialog(),disablepassword()])
    keyButton.pack(side=LEFT)

    usepass=tk.Button(newWindow, text="Use password",command=lambda :[openpassword(),disablekey()])
    usepass.pack(side=RIGHT)

    decrButton=tk.Button(newWindow,text="DECRYPT NOW",command=decrypfunc)
    decrButton.pack(in_=bottom)

    newWindow.protocol("WM_DELETE_WINDOW", on_close)


root.resizable(0,0)
canvas=tk.Canvas(root,width=200,height=20)
canvas.pack()
encryptMode= tk.Button(text="ENCRYPT",command= encryptWindow)
decryptMode= tk.Button(text="DECRYPT",command= decryptWindow)

encryptMode.pack(side=LEFT)
decryptMode.pack(side=RIGHT)
root.mainloop()
