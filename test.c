/**
  Copyright (C) 2017 Odzhan. All Rights Reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are
  met:

  1. Redistributions of source code must retain the above copyright
  notice, this list of conditions and the following disclaimer.

  2. Redistributions in binary form must reproduce the above copyright
  notice, this list of conditions and the following disclaimer in the
  documentation and/or other materials provided with the distribution.

  3. The name of the author may not be used to endorse or promote products
  derived from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY AUTHORS "AS IS" AND ANY EXPRESS OR
  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
  ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
  POSSIBILITY OF SUCH DAMAGE. */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "rsa.h"

void test_sign(void) {
  RSA *rsa = rsa_open();
  
  if (rsa != NULL) {
    if (rsa_read_key(rsa, "private.pem", RSA_PRIVATE_KEY)) {
      if (rsa_sign(rsa, "private.pem", "signature.txt")) {
        printf ("\nsigned");
      } else printf ("\nrsa_sign");
    } else printf ("\nrsa_read_key");
    rsa_close(rsa);
  } else printf ("\nrsa_open");
}

int main(int argc, char *argv[])
{
    RSA  *rsa;

    rsa = rsa_open();
    
    if (rsa != NULL) {
      if (rsa_genkey(rsa, 1024)) {
        rsa_write_key(rsa, "public.pem",  RSA_PUBLIC_KEY);
        rsa_write_key(rsa, "private.pem", RSA_PRIVATE_KEY);
        
        test_sign();
        
      } else printf ("\nrsa_genkey() failed");
      rsa_close(rsa);
    } else printf ("\nrsa_open() failed");
    return 0;  
}