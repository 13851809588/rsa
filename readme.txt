
[ generate key pair

  openssl genrsa -out private.pem 1024
  openssl rsa -in private.pem -pubout -out public.pem

[ signing
  
  openssl dgst -sha256 -sign private.pem -out readme.sig readme.txt
  openssl base64 -in readme.sig -out readme.sig.txt
  
[ verify

  openssl base64 -d -in readme.sig.txt -out readme.sig
  openssl dgst -sha256 -verify public.pem -signature readme.sig readme.txt
  
ifinee  