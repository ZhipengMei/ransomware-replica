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
    * [3. RSA File](#3-rsa-file-ransomware)
      * [System Requirements](#system-requirements)
      * [macOS Installation](#macos-installation)
      * [Linux Installation](#linux-installation)
      * [Windows Installation](#windows-installation)
      * [Sample output](#sample-output)



<!--
  * [Installation](#installation)
  * [Usage](#usage)
    * [Local files](#local-files)
    * [Remote files](#remote-files)
    * [Multiple files](#multiple-files)
    * [Combo](#combo)
  * [Tests](#tests)
  * [Dependency](#dependency)

-->


Documentations
==============

1: [Transport Layer Security](https://en.wikipedia.org/wiki/Transport_Layer_Security)
=============

#### Step 1:

Tutorial: [Setting up an AWS EC2 Instance with LAMP and GIT](http://devoncmather.com/setting-aws-ec2-instance-lamp-git/)

[Resources](https://github.com/AnimeMei/GroupNumberOne/tree/master/1_TSL_Server)

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

3: RSA File (Ransomware)
===========

[View Source Code](https://github.com/AnimeMei/GroupNumberOne/blob/master/3_RSA_File/drafts/RSA%20File%20(CECS%20378%20GroupNumberOne).ipynb)

## System Requirements
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
