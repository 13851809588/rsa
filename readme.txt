
[ generate key pair

  openssl genrsa -aes128 -passout pass:<phrase> -out private.pem 4096
  openssl rsa -in private.pem -passin pass:<phrase> -pubout -out public.pem

[ signing
  
  openssl dgst -sha256 -sign <private-key> -out /tmp/sign.sha256 <file>
  openssl base64 -in /tmp/sign.sha256 -out <signature>
  
[ verify

  openssl base64 -d -in <signature> -out /tmp/sign.sha256
  openssl dgst -sha256 -verify <pub-key> -signature /tmp/sign.sha256 <file>  