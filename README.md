Group Number One
================
**Welcome to Group Number One repository**

This repository contains course work alongside with **[CECS 378: Introduction to Computer Security Principles](http://web.csulb.edu/divisions/aa/catalog/current/coe/computer_engineering/cecs_ud.html)**. The purpose of having course works as open source is for students to interact and help each other to learn more about cyber security concepts. Documentations are tutorials/questionnaires to guide beginners step by step to start and finish the project.

Table of contents
=================

  * [Group Number One](#group-number-one)
  * [Documentations](#documentations)
    * [1. Transport Layer Security](#1-transport-layer-security)
      * [Step 1: Setting up an AWS EC2 Instance with LAMP and GIT](#step-1)
      * [Step 2: SSL Config Apache2](#step-2)
      * [Step 3: Redirect to HTTPS from HTTP](#step-3)
      * [Step 4: Certbot](#step-4)
      * [Step 5: SSLlabs](#step-5)
    * [2. Encryption](#2-encryption)
    * [3. RSA File](#3-rsa-file)
      * [RSA System Requirements](#rsa-system-requirements)
      * [macOS Installation](#macos-installation)
      * [Linux Installation](#linux-installation)
      * [Windows Installation](#windows-installation)
      * [Sample output](#sample-output)
     * [4. RESTful API](#4-restful-api)
       * [API System Requirements](#api-system-requirements)
       * [How to](#how-to)
       * [HTTP endpoint](#http-endpoint)
       * [Note: MongoDB control](#note-mongodb-control)
       * [POST/GET in Python](#postget-in-python)
       * [Resources](#resources)

Documentations
==============

1: [Transport Layer Security](https://en.wikipedia.org/wiki/Transport_Layer_Security)
=============

<img src="https://www.happyhounddogresorts.com/wp-content/uploads/2017/08/HTTPS_icon.png" alt="http secure" height="50" > The purpose of this project is to setup [AWS EC2](https://aws.amazon.com/ec2/) instance. Connect **.me** domain name from [Namecheap](https://www.namecheap.com/). Clone github repository to AWS server. Setup TLS so that [HTTPS](https://en.wikipedia.org/wiki/HTTPS) appears in the URL because website is secured :ok_hand: by an TSL certificate.

#### Step 1:

Tutorial: [Setting up an AWS EC2 Instance with LAMP and GIT](http://devoncmather.com/setting-aws-ec2-instance-lamp-git/)

[Resources](https://github.com/AnimeMei/GroupNumberOne/tree/master/1_TSL_Server)

Once the setup process is finished, connect to Your Linux Instance Using SSH (.pem & public DNS)

    ssh -i /path/my-key-pair.pem ubuntu@ec2-.amazonaws.com-my-Public-DNS-(IPv4)-address
    

#### Step 2:
SSL Config [Apache2](https://en.wikipedia.org/wiki/Apache_HTTP_Server):
Include the following lines into the **ssl config** file

```
LoadModule ssl_module modules/mod_ssl.so

<IfModule mod_ssl.c>

SSLEngine on
SSLProtocol -all +TLSv1.2

SSLHonorCipherOrder On

SSLCipherSuite ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-CBC-SHA384:ECDHE-RSA-AES256-CBC-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:!aNULL:!MD5:!DSS
```

Modify the **httpd.conf** config file
```
<VirtualHost *:443>

ServerName NAME.name
ServerAlias www.NAME.name
Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains"

SSLEngine on
SSLCertificateFile    PATH-TO-cert.pem-FILE
SSLCertificateKeyFile PATH-TO-privkey.pem-FILE
SSLCertificateChainFile PATH-TO-fullchain.pem-FILE 

</VirtualHost>
```
#### Step 3:
To force a redirect to HTTPS from HTTP include the below in your configuration
```
<VirtualHost *:80> 
ServerName Name.name
  Redirect permanent / https://Name.name/
</VirtualHost>
```
[Resources](https://github.com/AnimeMei/GroupNumberOne/blob/master/1_TSL_Server/Setup_Server_with_LAMP/SSL%20Config%20Apache2.txt)

#### Step 4:
Deploy Let's [Encrypt certificates](https://en.wikipedia.org/wiki/Let%27s_Encrypt)
Automatically enable [HTTPS](https://en.wikipedia.org/wiki/HTTPS) on your website with [EFF](https://www.eff.org/about)'s [**Certbot**](https://certbot.eff.org/#ubuntuxenial-apache)

#### Step 5:
Site's [certificate](https://en.wikipedia.org/wiki/Certificate_authority) and configuration testing with [**SSLlabs**](https://www.ssllabs.com/)
 
 Sample output:
 ![ssllabs test result](https://github.com/AnimeMei/GroupNumberOne/blob/master/sample_output/ssl_result.png)

2: [Encryption](https://en.wikipedia.org/wiki/Encryption)
============

The purpose of this project is to create 3 functions to encrypt a message, a file or RSA encrypt a file (private/public keys required). :blowfish:

[Source Code](https://github.com/AnimeMei/GroupNumberOne/blob/master/2_Encryption/CECS%20378%20Encryption%20Lab_GroupNumberOne.ipynb)
|
File format: [Jupyter Notebook](http://jupyter.org/) with [Python3](https://www.python.org/download/releases/3.0/)
|
Library: [Cryptography hazmat](https://cryptography.io/en/latest/hazmat/primitives/)

### (C, IV)= Myencrypt(message, key)

Sample output:
```
Encrypted Message:
(b'\xe0\t\xb1\x17\x82\xa8o\xec\xf9\x1c^\x9b\xa6b\x0b\xb9[cH\xba\xc3\xcb\xe4\xca6SM\xdb\x9e\xe8\x7f\xb5', b'\x9c|Xk\xff\x15\xc3\xc5\xff\x96Y\xce\x9d\x8d\xd7\x0b')

Dencrypted Message:
'a secret message'
```

### (C, IV, key, ext)= MyfileEncrypt (filepath)

Sample output:

```
Enter a file path for encrypted file output such as "encrypted_image": enc_file
Enter a file path for previously encrypted file: enc_file
Enter a file path for decrypted file output such as "decrypted_image": dec_file
```
### (RSACipher, C, IV, ext)= MyRSAEncrypt(filepath, RSA_Publickey_filepath)

Sample output:

```
Enter a file path for encrypted file output such as "encrypted_image": enc_file2
Enter a file path for previously encrypted file: enc_file2
Enter a file path for decrypted file output such as "decrypted_image": dec_file2
```

3: RSA File
===========

THe purpose of this file is to build a simple version of Ransomeware which only encrypt a specified directory when run by user manually. Original files will be encrypted and output as JSON files to replace the original files. Private and public keys are generated in the key folder. (:exclamation: :exclamation::exclamation::exclamation:Warning :warning: : do not encrypt important files nor delete private key.)

[View Source Code](https://github.com/AnimeMei/GroupNumberOne/blob/master/3_RSA_File/drafts/RSA%20File%20(CECS%20378%20GroupNumberOne).ipynb)

## RSA System Requirements
 [Python 3.6](https://www.python.org/downloads/release/python-361/) | [Cryptography hazmat](https://cryptography.io/en/latest/hazmat/primitives/)

### macOS Installation:
    git clone https://github.com/AnimeMei/GroupNumberOne.git
    cd GroupNumberOne/3_RSA_File

Execute the project:

    chmod +x exe/run_encrypt.sh
    chmod +x exe/run_decrypt.sh
    
    ./exe/run_encrypt.sh
    ./exe/run_decrypt.sh

For macOS environment installed python 3 alongside with the default python 2.7, execute the project with:
    
    chmod +x exe/encrypt.sh
    chmod +x exe/decrypt.sh
    
    ./exe/encrypt.sh
    ./exe/decrypt.sh
    
    
### Linux Installation:
    git clone https://github.com/AnimeMei/GroupNumberOne.git
    cd GroupNumberOne/3_RSA_File

Execute the project:

    chmod +x exe/run_encrypt.sh
    chmod +x exe/run_decrypt.sh
    
    ./exe/run_encrypt.sh
    ./exe/run_decrypt.sh

### Windows Installation:
    git clone https://github.com/AnimeMei/GroupNumberOne.git
    cd GroupNumberOne/3_RSA_File/exe
    
Move **FileMacEncrypt.exe** to a directory contains files ready to encrypt.
    
    GroupNumberOne/3_RSA_File/
    |-- exe/ 
    |   |-- FileMacEncrypt.exe
    
move .exe file
    
    MyFolder/
    |-- FileMacEncrypt.exe
    |-- file1.jpg
    |-- file2.png

E.g. **file1.jpg** and **file2.png** will be encrypted if executed.
Run **FileMacEncrypt.exe** to encrypt files within the same directory.
    
### Sample output:

Move files into **GroupNumberOne/3_RSA_File** directory for encryption:
  
    GroupNumberOne/3_RSA_File/
    |-- exe/ 
    |   |-- encrypt.sh
    |   |-- decrypt.sh
    |   |-- FileMacEncrypt.exe
    |   |-- src/
    |       |-- RSA_file_Encrypt.py
    |       |-- RSA_file_Decrypt.py
    |       |-- FileEncryptMAC/
    |           |-- _init_.py
    |           |-- FileEncryptMAC.py
    |
    |-- hello.jpg
    |-- hi.png
    
E.g. **hello.jpg** and **hi.png** will be encrypted if executed.

Or move **exe** folder to a directory contains files ready to encrypt.

    MyFolder/
    |-- exe/ 
    |   |-- encrypt.sh
    |   |-- decrypt.sh
    |   |-- FileMacEncrypt.exe
    |   |-- src/
    |       |-- RSA_file_Encrypt.py
    |       |-- RSA_file_Decrypt.py
    |       |-- FileEncryptMAC/
    |           |-- _init_.py
    |           |-- FileEncryptMAC.py
    |
    |-- hello.jpg
   
E.g. **hello.jpg** will be encrypted if executed.

#### Execution on macOS & Linux

**./exe/run_encrypt.sh**

    MyFolder/
    |-- exe/ 
    |   |-- encrypt.sh
    |   |-- decrypt.sh
    |   |-- src/
    |       |-- RSA_file_Encrypt.py
    |       |-- RSA_file_Decrypt.py
    |       |-- FileEncryptMAC/
    |           |-- _init_.py
    |           |-- FileEncryptMAC.py
    |
    |-- hello.jpg
    
```
Success: Created "public.pem" and "private.pem" 
MyfileEncryptMAC...running
Success: Encryption finished.
Success: HMAC tag finished.
MyencryptMAC complete.
Success: Encrypted file with a tag.
Complete: Create JSON file named "hi.encrypted.json".
```

    MyFolder/
    |-- exe/ 
    |   |-- encrypt.sh
    |   |-- decrypt.sh
    |   |-- src/
    |       |-- RSA_file_Encrypt.py
    |       |-- RSA_file_Decrypt.py
    |       |-- FileEncryptMAC/
    |           |-- _init_.py
    |           |-- FileEncryptMAC.py
    |
    |-- hello.encrypted.json

**./exe/run_decrypt.sh**

    MyFolder/
    |-- exe/ 
    |   |-- encrypt.sh
    |   |-- decrypt.sh
    |   |-- src/
    |       |-- RSA_file_Encrypt.py
    |       |-- RSA_file_Decrypt.py
    |       |-- FileEncryptMAC/
    |           |-- _init_.py
    |           |-- FileEncryptMAC.py
    |
    |-- hello.encrypted.json
    
```
MyfileDecryptMAC...running
Success: Tag verified.
MydecryptMAC Complete.

Success: Decrypted file with a tag. 

Complete: Decrypted file named "hello.png".
```
        MyFolder/
    |-- exe/ 
    |   |-- encrypt.sh
    |   |-- decrypt.sh
    |   |-- src/
    |       |-- RSA_file_Encrypt.py
    |       |-- RSA_file_Decrypt.py
    |       |-- FileEncryptMAC/
    |           |-- _init_.py
    |           |-- FileEncryptMAC.py
    |
    |-- hello.jpg

4: RESTful API
===========

Proeject 3 [RSA file](#3-rsa-file) was required to generate both private and public keys for encrytion and decryption. However, outputing private key on the device is no fun :snail:. The purpose of this project is to create an RESTful API. POST the private key information to the server and only output public on device. 

Public key on the device is for encryption. Private key is for decryption which requires a GET APi call from the server.

[Source Code](https://github.com/AnimeMei/GroupNumberOne/tree/master/4_API/rsa_Api): Node.js & MongoDB setup | [Source Code](https://github.com/AnimeMei/GroupNumberOne/blob/master/3_RSA_File/src/HTTP%20RSA%20File%20(CECS%20378%20GroupNumberOne).ipynb): RSA Encryption & API call

## API System Requirements

[npm](https://www.npmjs.com/) | [Node.js](https://nodejs.org/en/) | [MongoDB](https://www.mongodb.com/) | [Atom](https://atom.io/) | [Postman](https://www.getpostman.com/) | [AWS EC2](#step-1) Instance with LAMP and GIT | [Homebrew](https://brew.sh/) for macOS | [Express](http://expressjs.com/) | [nodemon](https://nodemon.io/) | [mongoose](http://mongoosejs.com/)

## How to

* Step 1: Build Node.js RESTful APIs [Tutorial](https://www.codementor.io/olatundegaruba/nodejs-restful-apis-in-10-minutes-q0sgsfhbd). Follow the tutorial to **create** an api. 

* Step 2: **Push** the source code to a github repository. 

You can proceed to the steps below using ssh in terminal to connect to AWS.

* Step 3: **Clone** or **Pull** the github repository to the AWS server. 

Once your api source code is in AWS server. 

* Step 4: Activate MongdDB with ```mongod```.

You can press ```ctrl+z``` then enter ```bg 1``` in the terminal to put MongoDB running in the background.

* Step 5: Run server.js file with ```node server.js``` or ```npm run start```.

You can press ```ctrl+z``` then enter ```bg 2``` in the terminal to leave the server running in the background.

```exit```

:+1: You may now test your API with Postman. :shipit:

### HTTP endpoint

Edit inbound rule in your instance's Security Groups.

![security group edit inbouds](https://cdn-images-1.medium.com/max/1000/1*CuzuWfaIsittNBeAhU2HcQ.png)

your-Public-DNS-address:3000/tasks

looks something like http://ec2.compute.amazonaws.com:3000/tasks

Connect to this address for any POST/GET request.

## Note: MongoDB control

For any reason that you would like to clear all contents in your MongoDB database.

Simply enter ```mongo``` then ```show dbs```

You can choose a database to use such as ```use mydb``` then ```db.dropDatabase()``` and finally ```exit```

## Note: AWS control

##### Another way to keep MongoDb and the server keeps running even after logout.

First execute the command ```screen```

Then run your server using ```mongod```

Then detach it by pressing ```ctrl+a``` and then pressing ```d```

```screen```

```node server.js```

```ctrl+a```

```d```

```exit```

Now the server is running.

##### Terminating process:
```ps -a``` or ```ps ax``` to list running process.
```kill pid``` to terminate a process.

## POST/GET in Python
```python
import requests

url = 'http://ec2.compute.amazonaws.com:3000/tasks'

# POST
post_request = requests.post(url, data={'name': 'My name is cutie_pie !!!'})

# GET
resp = requests.get(url=url)
data = json.loads(resp.text)
```

## Resources: 

#### [Tutorial](http://docs.aws.amazon.com/sdk-for-javascript/v2/developer-guide/setting-up-node-on-ec2-instance.html): Setting Up Node.js on an Amazon EC2 Instance
#### [Tutorial](https://www.digitalocean.com/community/tutorials/how-to-install-mongodb-on-ubuntu-16-04): Install MongoDB on Ubuntu 16.04
