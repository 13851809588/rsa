
## About ##

rsa_tool provides a working example in C of how to use Microsoft Crypto API to use RSA private and public keys to digitally sign and verify the integrity of files.

The private and public keys must be stored in PEM (Privacy Exchange Mail) format.
Signatures should be stored as Base64 which is essentially same as PEM except you don't require specific headers for the signature.

See more info about tool and how it works [here](http://stosd.wordpress.com/capi-openssl/)

## Building ##

This should compile without error using msvc.bat or mingw.bat (provided you have a recent copy of Mingw installed)

* **MSVC**

	cl /O2 /Os rsa_tool.c rsa.c encode.c memory.c 

* **Mingw**
	
	gcc -O2 -Os rsa_tool.c rsa.c encode.c memory.c -lcrypt32 -lshlwapi -orsa_tool

## Usage ##

![alt text](https://github.com/odzhan/rsa/blob/master/img/usage.png)

* **Generating RSA Key**
 
Before anything else, generate an RSA key pair. Crypto API will determine if the key length you provide is acceptable.

![alt text](https://github.com/odzhan/rsa/blob/master/img/generate.png)

* **Signing a file**

Simply supply a process name/process id along with PIC/DLL file or command line. Let's say we want to inject code into internet explorer.

![alt text](https://github.com/odzhan/rsa/blob/master/img/sign.png)

* **Verifying a file**

Using the public key, we can verify the signature and integrity of file with the following command.

![alt text](https://github.com/odzhan/rsa/blob/master/img/verify.png)

[@odzhancode](https://www.twitter.com/odzhancode "Follow me on Twitter")

4/22/2017 10:13:30 PM 
