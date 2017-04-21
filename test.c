

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

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
  printf("  [ usage: rsa_test [options]\n");
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