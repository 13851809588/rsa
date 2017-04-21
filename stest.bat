openssl rsa -text -inform PEM -in public.pem -pubin
openssl rsa -text -inform PEM -in private.pem
openssl dgst -sha256 -sign private.pem -out rsa.c.sha256 rsa.c
openssl dgst -sha256 -verify public.pem -signature rsa.c.sha256 rsa.c