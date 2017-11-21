# *Group Number One*

**Welcome to Group Number One repository**

This repository contains course work alongside with **[CECS 378: Introduction to Computer Security Principles](http://web.csulb.edu/divisions/aa/catalog/current/coe/computer_engineering/cecs_ud.html)**. The purpose of having course works as open source is for students to interact and help each other to learn more about cyber security concepts. Documentations are tutorials/questionnaires to guide beginners step by step to start and finish the project.

# Documentations

## [1. Transport Layer Security](https://github.com/AnimeMei/GroupNumberOne/tree/master/1.%20TSL%20Server)

* [Setting up an AWS EC2 Instance with LAMP and GIT](https://github.com/AnimeMei/GroupNumberOne/blob/master/1.%20TSL%20Server/Setup%20Server%20with%20LAMP/Setting%20up%20an%20AWS%20EC2%20Instance%20with%20LAMP%20and%20GIT.txt)
* [SSL Config Apache2](https://github.com/AnimeMei/GroupNumberOne/blob/master/1.%20TSL%20Server/Setup%20Server%20with%20LAMP/SSL%20Config%20Apache2.txt)
* [Certbot](https://certbot.eff.org/#ubuntuxenial-apache)
* Use [SSLlabs](https://www.ssllabs.com/)
 to test the site's certificate and configuration
 
 Sample output:
 ![ssllabs test result](https://github.com/AnimeMei/GroupNumberOne/blob/master/sample_output/ssl_result.png)

## [2. Encryption](https://github.com/AnimeMei/GroupNumberOne/blob/master/2.%20Encryption/CECS%20378%20Encryption%20Lab_GroupNumberOne.ipynb) ([Jupyter Notebook](http://jupyter.org/) with [Python3](https://www.python.org/download/releases/3.0/))
* (C, IV)= Myencrypt(message, key)

Sample output:

![Myencrypt output](https://github.com/AnimeMei/GroupNumberOne/blob/master/sample_output/encrypt1.png)

* (C, IV, key, ext)= MyfileEncrypt (filepath)

Sample output:

![MyfileEncrypt output](https://github.com/AnimeMei/GroupNumberOne/blob/master/sample_output/encrypt2.png)

* (RSACipher, C, IV, ext)= MyRSAEncrypt(filepath, RSA_Publickey_filepath)

Sample output:

![MyRSAEncrypt output](https://github.com/AnimeMei/GroupNumberOne/blob/master/sample_output/encrypt3.png)
