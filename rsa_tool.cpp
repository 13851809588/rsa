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

#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstring>

#include "rsa.h"

char* getparam (int argc, char *argv[], int *i)
{
    int n=*i;
    if (argv[n][2] != 0) {
      return &argv[n][2];
    }
    if ((n+1) < argc) {
      *i=n+1;
      return argv[n+1];
    }
    printf ("  [ %c%c requires parameter\n", argv[n][0], argv[n][1]);
    exit (0);
}

void usage (void)
{
    printf("  [ usage: rsa_tool [options]\n");
    printf("     -key num         generate RSA key pair of num-bits\n"); 
    printf("     -sign   file     sign digest using private key in file\n");
    printf("     -verify file     verify a signature using public key in file\n");
    printf("     -out filename    output to filename rather than stdout\n");
    printf("     -signature file  signature to verify\n\n");
    exit (0);
}

int main(int argc, char *argv[])
{
  int  i, g=0, s=0, v=0;
  char opt;
  char *file, *sig;
  int  keyLen;
  RSA  *rsa;
  
  printf ("\n\n  [ RSA test for Crypto API\n\n");
  
  for (i=1; i<argc; i++)
  {
    if (argv[i][0]=='-' || argv[i][0]=='/')
    {
      opt=argv[i][1];
      switch (opt)
      {
        case 'g': // generate RSA key pair
          g=1;
          keylen=atoi(getparam(argc, argv, &i));
          break;
        case 'm': // sign a message using RSA (just for testing)
          input=getparam (argc, argv, &i);
          s=1;
          break;
        case 'v': // verify RSA signature (just for testing)
          signature=getparam (argc, argv, &i);
          v=1;
          break;
        default:
          usage();
          break;
      }
    }
  }  
  rsa = rsa_open();
    
    if (rsa != NULL) {
      if (rsa_genkey(rsa, 1024)) {
        rsa_save_file(rsa, "public.pem",  RSA_PUBLIC_KEY);
        rsa_save_file(rsa, "private.pem", RSA_PRIVATE_KEY);
      }
      rsa_close(rsa);
    }
    return 0;  
}