

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "rsa.h"

int main(void)
{
    RSA *rsa = rsa_open();
    
    if (rsa != NULL) {
      if (rsa_genkey(rsa, 1024)) {
        rsa_save(rsa, "public.pem",  RSA_PUBLIC_KEY);
        rsa_save(rsa, "private.pem", RSA_PRIVATE_KEY);
      }
      rsa_close(rsa);
    }
    return 0;  
}