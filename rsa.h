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
  
#ifndef RSA_H
#define RSA_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stddef.h>
#include <sys/stat.h>

#include "encode.h"

#ifdef _MSC_VER
#pragma comment (lib, "advapi32.lib")
#endif

#define RSA_PUBLIC_KEY  1
#define RSA_PRIVATE_KEY 2

typedef struct _RSA_t {
  HCRYPTPROV prov;
  HCRYPTKEY  privkey, pubkey;
  DATA_BLOB  priv, pub;
  DWORD      error;
} RSA;

#ifdef __cplusplus
extern "C" {
#endif

  RSA* rsa_open(void);
  int rsa_genkey(RSA*, int);
  
  int rsa_load(RSA*, const char*, int);
  int rsa_load_file(RSA*, const char*, int);
  
  int rsa_save(RSA*, const char*, int);
  int rsa_save_file(RSA*, const char*, int);
  
  void rsa_close(RSA*);
  const char *rsa_error(void);

#ifdef __cplusplus
}
#endif
  
#endif
  