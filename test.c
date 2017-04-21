

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "rsa.h"

/**
-g <bits> generate RSA key pair and save to PEM files
-s <msg>  sign a message using private key
-v <msg>  verify a message using public key

*/
int main(void)
{
    RSA *rsa = rsa_open();
    
    if (rsa != NULL) {
      if (rsa_genkey(rsa, 1024)) {
        rsa_save_file(rsa, "public.pem",  RSA_PUBLIC_KEY);
        rsa_save_file(rsa, "private.pem", RSA_PRIVATE_KEY);
      }
      rsa_close(rsa);
    }
    return 0;  
}