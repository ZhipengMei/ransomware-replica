# *Group Number One*

**Welcome to Group Number One repository**

This repository contains course work alongside with **[CECS 378: Introduction to Computer Security Principles](http://web.csulb.edu/divisions/aa/catalog/current/coe/computer_engineering/cecs_ud.html)**. The purpose of having course works as open source is for students to interact and help each other to learn more about cyber security concepts. Documentations are tutorials/questionnaires to guide beginners step by step to start and finish the project.

# Documentations

## 1. [Transport Layer Security](https://en.wikipedia.org/wiki/Transport_Layer_Security)

Tutorial: [Setting up an AWS EC2 Instance with LAMP and GIT](http://devoncmather.com/setting-aws-ec2-instance-lamp-git/)

#### Step 1:
[Setting up an AWS EC2 Instance with LAMP and GIT](https://github.com/AnimeMei/GroupNumberOne/blob/master/1.%20TSL%20Server/Setup%20Server%20with%20LAMP/Setting%20up%20an%20AWS%20EC2%20Instance%20with%20LAMP%20and%20GIT.txt)

[Resources](https://github.com/AnimeMei/GroupNumberOne/blob/master/1.%20TSL%20Server/Setup%20Server%20with%20LAMP/Setting%20up%20an%20AWS%20EC2%20Instance%20with%20LAMP%20and%20GIT.txt)

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

To force a redirect to HTTPS from HTTP include the below in your configuration
```
<VirtualHost *:80> 
ServerName Name.name
  Redirect permanent / https://Name.name/
</VirtualHost>
```
[Resources](https://github.com/AnimeMei/GroupNumberOne/blob/master/1.%20TSL%20Server/Setup%20Server%20with%20LAMP/SSL%20Config%20Apache2.txt)

#### Deploy Let's Encrypt certificates
Automatically enable HTTPS on your website with EFF's [Certbot](https://certbot.eff.org/#ubuntuxenial-apache)

#### Site's certificate and configuration testing with [SSLlabs](https://www.ssllabs.com/)
 
 Sample output:
 ![ssllabs test result](https://github.com/AnimeMei/GroupNumberOne/blob/master/sample_output/ssl_result.png)

## 2. [Encryption](https://github.com/AnimeMei/GroupNumberOne/blob/master/2.%20Encryption/CECS%20378%20Encryption%20Lab_GroupNumberOne.ipynb)

File format: [Jupyter Notebook](http://jupyter.org/) with [Python3](https://www.python.org/download/releases/3.0/)

Library used: [cryptography](https://cryptography.io/en/latest/hazmat/primitives/)

### (C, IV)= Myencrypt(message, key)

Sample output:

![Myencrypt output](https://github.com/AnimeMei/GroupNumberOne/blob/master/sample_output/encrypt1.png)

### (C, IV, key, ext)= MyfileEncrypt (filepath)

Sample output:

![MyfileEncrypt output](https://github.com/AnimeMei/GroupNumberOne/blob/master/sample_output/encrypt2.png)

### (RSACipher, C, IV, ext)= MyRSAEncrypt(filepath, RSA_Publickey_filepath)

Sample output:

![MyRSAEncrypt output](https://github.com/AnimeMei/GroupNumberOne/blob/master/sample_output/encrypt3.png)

## 3. [RSA File](https://github.com/AnimeMei/GroupNumberOne/blob/master/3.%20RSA%20File/RSA%20File%20-%20CECS%20378%20-%20GroupNumberOne.ipynb)
