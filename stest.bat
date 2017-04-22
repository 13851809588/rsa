openssl rsa -text -inform PEM -in public.pem -pubin
openssl rsa -text -inform PEM -in private.pem
openssl dgst -sha256 -sign private.pem -out signature.txt private.pem
openssl dgst -sha256 -verify public.pem -signature signature.txt private.pem