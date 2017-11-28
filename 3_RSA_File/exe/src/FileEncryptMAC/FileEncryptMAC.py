import os
import sys
import base64
import cryptography
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, serialization, hashes, asymmetric as asymm, hashes, hmac
from cryptography.hazmat.primitives.asymmetric import rsa
import json

class FileEncryptMAC:

    #--- Part 1: (C, IV, tag)= MyencryptMAC(message, EncKey, HMACKey) ---

    # encryption method AES-CBC-256, Encrypt-then-MAC(SHA256)
    def MyencryptMAC(self, message, EncKey, HMACKey):

        #--- STEP 1: Encrypt ---

        #check key length
        if len(EncKey)<32 or len(HMACKey)<32:
            print("Error: key lengthis less than 32 bytes.")
            return

        # convert message to bytes. Pass if message is already bytes type.
        try:
            message = message.encode()#convert string to bytes
        except:
            pass

        # encrypt a message
        try:
            IV = os.urandom(16)   #generate an Initialization vector

            # pad the message
            padder = padding.PKCS7(128).padder()
            padded_data = padder.update(message) + padder.finalize()
            message = padded_data

            #calling the default AES CBC mode
            cipher = Cipher(algorithms.AES(EncKey), modes.CBC(IV), backend=default_backend())
            #creating an encryptor object
            encryptor = cipher.encryptor()
            #generating cipher text
            C = encryptor.update(message) + encryptor.finalize()

            print("Success: Encryption finished.")
        except:
            print("Error: Encryption failed.")
            return


        #--- STEP 2: HMAC ---
        try:
            # create a tag
            tag = hmac.HMAC(HMACKey, hashes.SHA256(), backend=default_backend())
            tag.update(C)
            tag = tag.finalize()

            print("Success: HMAC tag finished.")
            print("MyencryptMAC complete.")
            return(C, IV, tag)
        except:
            print("Error: HMAC tag failed.")
            return



    # MACVerification-then-Decrypt
    def MydecryptMAC(self, C, IV, tag, EncKey, HMACKey):

        #Step 1: Verify
        # create HMAC_tag
        h = hmac.HMAC(HMACKey, hashes.SHA256(), backend=default_backend())
        h.update(C)
        h = h.finalize()

        # compare HMAC_tag with tag belongs to encrypted content
        if h == tag:
            print("Success: Tag verified.")
            cipher = Cipher(algorithms.AES(EncKey), modes.CBC(IV), backend=default_backend())
            #creating a decryptor object
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(C) + decryptor.finalize()

            try:
                #unpad the plaintext
                unpadder = padding.PKCS7(128).unpadder()
                pt = unpadder.update(plaintext) + unpadder.finalize()
                print("MydecryptMAC Complete.\n")
                return plaintext
            except:
                #plaintext does not require unpadding
                print("MydecryptMAC Complete.\n")
                return plaintext

        else:
            print("Error: Tag verified failed.\n")
            return


    #--- Part 2: (C, IV, tag, Enckey, HMACKey, ext)= MyfileEncryptMAC(filepath) ---
    def MyfileEncryptMAC(self, filepath):

        try:
            #generate keys
            EncKey = os.urandom(32)
            HMACKey = os.urandom(32)
        except:
            print("NameError: name 'os' is not defined")
            return

        try:
            # Read the entire file as a single byte string
            with open(filepath, 'rb') as f:
                data = f.read()
        except:
            print("Error: filepath is invalid.")
            return

        try:
            try:
                result = self.MyencryptMAC(data, EncKey, HMACKey)
                print("Success: Encrypted file with a tag.")
            except:
                print("Error: MyencryptMAC failed.")
                return

            ext = os.path.splitext(filepath)[1]
            filename = os.path.basename(filepath)
            enc_filename = os.path.splitext(filename)[0] + ".encrypted" + ext
            result += (EncKey, HMACKey, ext)

#             # create a writable image and write the decoding result
#             input_enc_filepath = os.path.abspath(enc_filename)
#             image_result = open(input_enc_filepath, 'wb')
#             image_result.write(result[0])
#             print("Complete: Encrypted file named \"{}\".\n".format(input_enc_filepath))
            return result
        except:
            print("Error: MyfileEncryptMAC failed.\n")
            return


    # file dencryption algorithm
    def MyfileDecryptMAC(self, enc_filepath, C, iv, tag, key, h, ext):
        # cipher text as bytes
        data = C

        try:
            plaintext = self.MydecryptMAC(data, iv, tag, key, h)
            print("Success: Decrypted file with a tag. \n")

            dec_file_path = os.path.abspath(enc_filepath)
            a = os.path.basename(dec_file_path)
            c = os.path.splitext(a)
            d = os.path.splitext(c[0])
            dec_file_path = d[0]+ext

            image_result = open(dec_file_path, 'wb') # create a writable image and write the decoding result
            image_result.write(plaintext)
            print("Complete: Decrypted file named \"{}\".\n".format(dec_file_path))

        except:
            print("Error: MydecryptMAC failed.")


    #--- Part 3:  (RSACipher, C, IV, tag, ext)= MyRSAEncrypt(filepath, RSA_Publickey_filepath) ---

    #create public/private key pair
    def create_pem_key_pair(self):
        # create a directory to store PEM keys
        newpath = os.path.abspath("keys")
        if not os.path.exists(newpath):
            os.makedirs(newpath)

        # create key object
        backend = default_backend()
        key = rsa.generate_private_key(backend=backend, public_exponent=65537,key_size=2048)

        # private key
        private_key = key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
                )
        with open("keys/private.pem", 'wb') as private_pem:
            private_pem.write(private_key)
            private_pem.close()

        #public key
        public_key = key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
        with open("keys/public.pem", 'wb') as public_pem:
            public_pem.write(public_key)
            public_pem.close()

        print("Success: Created \"public.pem\" and \"private.pem\" ")


    def loadkeys(self):
        for root, dirs, files in os.walk("."):
            for file in files:
                if file.endswith(".pem"):
                    if file == "public.pem":
                        public_key_path = os.path.abspath(os.path.join(root, file))
                    if file == "private.pem":
                        private_key_path = os.path.abspath(os.path.join(root, file))
        return public_key_path, private_key_path


    #RSA encryption method
    def MyRSAEncryptMAC(self, file_path, RSA_Publickey_filepath):
        #encrypting an image file
        print("MyfileEncryptMAC...running")
        try:
            C, IV, tag, Enckey, HMACKey, ext = self.MyfileEncryptMAC(file_path)
        except:
            print("Error: MyfileEncryptMAC failed.\n")
            return

        try:
            with open(RSA_Publickey_filepath, "rb") as p_key:
                public_key = serialization.load_pem_public_key(p_key.read(),backend=default_backend())
        except:
            print("Error: Pem Public key's filepath is invalid.")
            return

        #obtain RSACipher
        try:
            RSACipher = public_key.encrypt(Enckey + "thisisabreakpoint".encode() +HMACKey, asymm.padding.OAEP(
                                                   mgf=asymm.padding.MGF1(algorithm=hashes.SHA256()),
                                                   algorithm=hashes.SHA256(),
                                                   label=None ))
        except:
            print("Error: RSACipher cannot be generated.")
            return

        return RSACipher, C, IV, tag, ext



    #RSA decryption method
    def MyRSADecryptMAC(self, RSACipher, enc_file_path, C, IV, tag, ext, RSA_Privatekey_filepath):

        try:
            with open(RSA_Privatekey_filepath, "rb") as Enckey:
                private_key = serialization.load_pem_private_key(Enckey.read(),password=None, backend=default_backend())
        except:
            print("Error: Pem private key's filepath is invalid.")

        try:
            key = private_key.decrypt(
                RSACipher,
                asymm.padding.OAEP(mgf=asymm.padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))

            # split the Enc_key and HMAC_key
            key_list = key.split("thisisabreakpoint".encode())
            Enckey, HMACKey = key_list[0], key_list[1]
        except:
            print("Error: Enc_key and HMAC_key cannot be generated from RSACipher.")


        print("MyfileDecryptMAC...running")
        try:
            self.MyfileDecryptMAC(enc_file_path, C, IV, tag, Enckey, HMACKey, ext)
        except:
            print("Error: MyfileDecryptMAC failed.\n")


            
            
    # -------------------------
    # Execution Functions Below
    # ------------------------


    ## 2: Encryption Function
    
    # Encryption useage
    def dir_encrypt(self):

        # 1: key check
        try:
            public_key_path, private_key_path = self.loadkeys()
        except:
            # generating public/private key pairs
            self.create_pem_key_pair()
            public_key_path, private_key_path = self.loadkeys()

        # get a list of files in a directory ready for encryption
        directory = os.getcwd()
        # get only file in directory
        files = [f for f in os.listdir(directory) if os.path.isfile(f)]
        # remove ".ipynb" and ".DS_Store" files
        files = [ x for x in files if ".ipynb" not in x
        and ".DS_Store" not in x
        and ".pem" not in x
        and ".json" not in x
        and ".py" not in x
        and ".md" not in x
        and ".sh" not in x]

        for file in files:
            filepath = os.path.abspath(file)

            try:
                RSACipher, C, IV, tag, ext = self.MyRSAEncryptMAC(filepath, public_key_path)
            except:
                print("Error: MyRSAEncryptMAC failed.")
                return

            # create JSON file with encrypted data
            try:
                data = {}
                data['RSACipher'] = RSACipher.decode('latin-1')
                data['C'] = C.decode('latin-1')
                data['IV'] = IV.decode('latin-1')
                data['tag'] = tag.decode('latin-1')
                data['ext'] = ext
            except:
                print("Error: Creating JSON object failed.")
                return

            try:
                filename = os.path.splitext(file)[0] + ".encrypted" + ".json"

                with open(filename, 'w') as outfile:
                    json.dump(data, outfile, indent=4)

                #remove original files
                os.remove(filepath)
                print("Complete: Create JSON file named \"{}\".\n".format(filename))
            except:
                print("Error: Creating JSON file failed.")
                return


    ## 3: Decryption Function
    # Decryption useage
    def dir_decrypt(self):

        # 1: key check
        try:
            public_key_path, private_key_path = self.loadkeys()
        except:
            # generating public/private key pairs
            self.create_pem_key_pair()
            public_key_path, private_key_path = self.loadkeys()

        # get a list of files in a directory ready for encryption
        directory = os.getcwd()
        # get only file in directory
        files = [f for f in os.listdir(directory) if os.path.isfile(f)]
        # remove ".ipynb" and ".DS_Store" files
        files = [ x for x in files if ".json" in x]

        for file in files:
            try:
                #opens the json file
                with open(file, 'r') as re:
                    json_data = json.load(re)
            except:
                print("Error: Cannot open JSON file.")
                return

            try:
                data_RSACipher = bytes(json_data["RSACipher"], 'latin-1')
                data_C = bytes(json_data["C"], 'latin-1')
                data_IV = bytes(json_data["IV"], 'latin-1')
                data_tag = bytes(json_data["tag"], 'latin-1')
                data_ext = json_data["ext"]
                filename = os.path.splitext(file)[0] + data_ext
            except:
                print("Error: Parse JSON data failed.")
                return

            try:
                enc_filepath = os.path.abspath(filename)
                self.MyRSADecryptMAC(data_RSACipher, file, data_C, data_IV, data_tag, data_ext, private_key_path)
                os.remove(file)
            except:
                print("Error: MyRSADecryptMAC failed.")
