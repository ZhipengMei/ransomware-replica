import os
import cryptography
import base64
import json
import time
import cryptography.hazmat.primitives.asymmetric as asymm
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes, hmac
from cryptography.hazmat.primitives import padding, serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa

# encryption method AES-CBC-256
def Myencrypt(message, key, h):
    
    #key length check
    if len(key)<32:
        return "Error: This place is full of land mines, dragons, and dinosaurs with laser guns. Increase you key length to upgrade your armor."
    
    try:
        message = message.encode()
    except:
        pass
    
    iv = os.urandom(16)   #generate an iv
    if len(message)%16 != 0:
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(message) + padder.finalize()
        message = padded_data
    
    #HMAC
    #calling the default AES CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    #creating an encryptor object
    encryptor = cipher.encryptor()
    #generating cipher text
    ct = encryptor.update(message) + encryptor.finalize()
    #return (ct, iv) 
    
    tag = hmac.HMAC(h, hashes.SHA256(), backend=default_backend())
    tag.update(ct)
    tag = tag.finalize()
    return (ct, iv, tag)
    

# decryption method
def Mydecrypt(ct, iv, tag, key, h):
    
    #Verify
    h = hmac.HMAC(h, hashes.SHA256(), backend=default_backend())
    h.update(ct)
    h = h.finalize()
    
    if h == tag:
        print("verified")
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        #creating a decryptor object
        decryptor = cipher.decryptor()
        pt = decryptor.update(ct) + decryptor.finalize()
        try:
            unpadder = padding.PKCS7(128).unpadder()
            pt = unpadder.update(pt) + unpadder.finalize()
            return pt
        except:
            return pt
    else:
        return("invalid")

# file encryption algorithm
def MyfileEncrypt(filepath):
    global fileCount
    fileCount += 1
    key = os.urandom(32)
    h = os.urandom(32)
    # Read the entire file as a single byte string
    with open(filepath, 'rb') as f:
        data = f.read()

    result = Myencrypt(data, key, h)
    ext = os.path.splitext(filepath)[1]
    result += (key, h, ext)
    
    image_result = open(filepath, 'wb') # create a writable image and write the decoding result
    image_result.write(result[0])
    
    return result

# file dencryption algorithm
def MyfileDecrypt(enc_filepath, iv, tag, key, h, ext):
    
    with open(enc_filepath, 'wb') as f:
        data = f.read()
    
    file_name = "decrypted_image" + ext
    plaintext = Mydecrypt(data, iv, tag, key, h)
    image_result = open(file_name, 'wb') # create a writable image and write the decoding result
    image_result.write(plaintext)



#create public/private key pair
def create_pem_key_pair():
    # create key object
    backend = default_backend()
    key = rsa.generate_private_key(backend=backend, public_exponent=65537,key_size=2048)
    
    # private key
    private_key = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
            )
    with open("private.pem", 'wb') as private_pem:
        private_pem.write(private_key)
        private_pem.close()
    
    #public key
    public_key = key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
    with open("public.pem", 'wb') as public_pem:
        public_pem.write(public_key)
        public_pem.close()
    
    
#RSA encryption method
def MyRSAEncrypt(file_path, RSA_Publickey_filepath):
    #encrypting an image file
    ct, iv, tag, key, h, ext = MyfileEncrypt(file_path)
    
    with open(RSA_Publickey_filepath, "rb") as p_key:
        public_key = serialization.load_pem_public_key(p_key.read(),backend=default_backend())
        
    #obtain RSACipher
    RSACipher = public_key.encrypt(key+ "break".encode() + h, asymm.padding.OAEP(
                                           mgf=asymm.padding.MGF1(algorithm=hashes.SHA256()),
                                           algorithm=hashes.SHA256(),
                                           label=None ))
    return RSACipher, ct, iv, tag, ext


#RSA decryption method
def MyRSADecrypt(RSACipher, ct, iv, tag, ext, RSA_Privatekey_filepath):

    with open(RSA_Privatekey_filepath, "rb") as key:
        private_key = serialization.load_pem_private_key(key.read(),password=None, backend=default_backend())

    key = private_key.decrypt(
        RSACipher,
        asymm.padding.OAEP(mgf=asymm.padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
    
    #split key into hmac and enc key
    key_list = key.split("break".encode())
    key, h = key_list[0], key_list[1]
    
    #decrypt the file
    MyfileDecrypt(ct, iv, tag, key, h, ext)
    

#execution code
fileCount = 0 #Number encrypted files so file is not overwritten

#Change directory to hello folder
os.chdir('hello')

#If keys do NOT exist in folder create keys
if (os.path.exists('./public.pem') != True):
    print("Creating keys...")
    create_pem_key_pair()
    
#Get files in folder
file_list = os.listdir()
dirLength = len(file_list) #Number of files

#List out the files
print(file_list)

js = {}

#If file is a PNG file, encrypt
for x in range(dirLength):
    if (os.path.splitext(file_list[x])[1] == ".png"):
        print("Encrypting " + file_list[x])
        RSACipher, ct, iv, tag, ext = MyRSAEncrypt(file_list[x], "public.pem")
        file_name = os.path.splitext(str(file_list[x]))[0]
        j = {}
        j[file_name] = []
        
        j[file_name].append({
                "RSACipher": RSACipher.decode('latin-1'),
                "CT": ct.decode('latin-1'),
                "IV": iv.decode('latin-1'),
                "Tag": tag.decode('latin-1'),
                "Ext": ext
                })
        js.update(j)

# Add to json file
with open('data.json', 'w') as outfile:
    json.dump(js, outfile, indent=4)

# Open json file
with open('data.json', 'r') as re:
    s = json.load(re)

# Decrypt files but currently not working
file_list = os.listdir()
print(file_list)
for file in file_list:
    if (os.path.splitext(file)[1] == ".png"):
        file_name = os.path.splitext(file)[0]
        print("Decrypting " + file)
        RSACipher2 = bytes(s[file_name][0]["RSACipher"], 'latin-1')
        ct2 = bytes(s[file_name][0]["CT"], 'latin-1')
        iv2 = bytes(s[file_name][0]["IV"], 'latin-1')
        tag2 = bytes(s[file_name][0]["Tag"], 'latin-1')
        ext2 = s[file_name][0]["Ext"]
        MyRSADecrypt(RSACipher2, ct2, iv2, tag2, ext2, './private.pem')
