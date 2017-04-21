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

#include "rsa.h"

/**
 *
 * open CSP and return pointer to RSA object
 *
 */
RSA* rsa_open(void)
{
    RSA *rsa = xmalloc(sizeof(RSA));

    if (rsa != NULL) {
      CryptAcquireContext(&rsa->prov, 
          NULL, NULL, PROV_RSA_FULL, 
          CRYPT_VERIFYCONTEXT | CRYPT_SILENT);
    }
    return rsa;
}
  
/**
 *
 * close CSP and release memory for RSA object
 *
 */  
void rsa_close(RSA *rsa) {
    if (rsa==NULL) return;
    
    // destroy key
    if (rsa->key != NULL) {
      CryptDestroyKey(key);
    }
    
    // release private key blob
    if (rsa->priv.pbData != NULL) {
      LocalFree(rsa->priv.pbData);
    }
    
    // release public key blob
    if (rsa->pub.pbData != NULL) {
      LocalFree(rsa->pub.pbData);
    }  
    
    // release csp
    CryptReleaseContext(rsa->prov, 0);
    
    // release object
    xfree(rsa);
}

/**
 *
 * generate new key pair of keyLen-bits
 *
 */   
int rsa_genkey(RSA* rsa, int keyLen) {  
    if (rsa==NULL) return -1;
    
    // destroy if already created
    if (rsa->key != NULL) {
      CryptDestroyKey(rsa->privkey);
    }
    
    // generate key pair
    CryptGenKey(rsa->prov, CALG_RSA_KEYX, 
      (keyLen << 16) | CRYPT_EXPORTABLE, 
      &rsa->privkey);
          
    rsa->error = GetLastError();
}

/**
 *
 * load public or pruvate key from PEM string
 *
 */
int rsa_load(RSA* rsa, const char* pem, int keyType) {
    LPVOID                  derData;
    PCRYPT_PRIVATE_KEY_INFO pki = 0;
    DWORD                   pkiLen;
    
    // decode base64 string ignoring headers
    derData = b64tobin(pemData, strlen(pem), 
      CRYPT_STRING_BASE64HEADER);
      
    if (derData != NULL) {
      // decode DER
      // is it a public key?       
      if (keyType == RSA_KEY_PUBLIC) {  
        // if public key blob already in rsa object
        // release it
        if (rsa->pub.pbData != NULL) {
          LocalFree(rsa->pub.pbData);
          rsa->pub.pbData = NULL;
          rsa->pub.cbData = 0;
        }              
        CryptDecodeObjectEx(
          X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
          X509_PUBLIC_KEY_INFO, derData, derLen, 
          CRYPT_DECODE_ALLOC_FLAG, NULL, 
          &rsa->pub.pbData, &rsa->pub.cbData);
      } else {
        // it's private
        if (rsa->priv.pbData != NULL) {
          LocalFree(rsa->priv.pbData);
          rsa->priv.pbData = NULL;
          rsa->priv.cbData = 0;
        }            
        // convert the PKCS#8 data to private key info
        if (CryptDecodeObjectEx(
              X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
              PKCS_PRIVATE_KEY_INFO, derData, derLen, 
              CRYPT_DECODE_ALLOC_FLAG, 
              NULL, &pki, &pkiLen))
        {
          // then convert the private key to private key blob
          CryptDecodeObjectEx(
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 
            PKCS_RSA_PRIVATE_KEY, 
            pki->PrivateKey.pbData, 
            pki->PrivateKey.cbData,
            CRYPT_DECODE_ALLOC_FLAG, NULL, 
            &rsa->priv.pbData, &rsa->priv.cbData); 
            
          // release private key info                
          LocalFree(pki);  
        }                 
      }            
      xfree(derData);  
    }
}        

/**
 *
 * load public or private key from PEM file
 *
 */    
int rsa_load_file(RSA* rsa, const char* pem, int keyType) {
    FILE                    *in;
    struct stat             st;
    LPVOID                  pemData; 
    
    if (rsa==NULL) return -1;
    if (pem==NULL) return -1;
    
    if (keyType!=RSA_KEY_PUBLIC && 
        keyType!=RSA_KEY_PRIVATE) return -1; 
    
    stat(pem, &st);
    if (st.st_size==0) return -1;
    
    // open PEM file
    in = fopen(pem, "rb");
    
    if (in != NULL) {
      // allocate memory for data
      pemData = xmalloc(st.st_size);
      if (pemData != NULL) {
        // read data
        size = fread(pemData, sizeof(char), st.st_size, in);
        if (size == st.st_size) {
          rsa_load(rsa, pemData, keyType);
        }
        xfree(pemData);
      }
      fclose(in);
    }
    return 1;  
}

const char public_start[]  = "-----BEGIN PUBLIC KEY-----\n";
const char public_end[]    = "-----END PUBLIC KEY-----\n";
  
const char private_start[] = "-----BEGIN PRIVATE KEY-----\n";
const char private_end[]   = "-----END PRIVATE KEY-----\n";

void rsa_write_pem(RSA *rsa, const char *pem, int keyType) {
    const char *s = public_start;
    const char *e = public_end;
    FILE       *out;
    
    out = fopen(pem, "wb");
        
    if (out != NULL) {
      fwrite(s, strlen(s), 1, out);
      fwrite(pem, strlen(pem), 1, out);
      fwrite(e, strlen(e), 1, out); 
      fclose(out);
    }   
}

/**
 *
 * save public or private key to PEM format
 *
 */   
int rsa_save_file(RSA* rsa, const char* pem, int keyType) {
    PCERT_PUBLIC_KEY_INFO pki;
    DWORD                 pkiLen;
    
    if (keyType == RSA_PUBLIC_KEY)
    {
      if (CryptExportPublicKeyInfo(rsa->prov, AT_KEYEXCHANGE, 
          X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 
          NULL, &pkiLen))
      {      
        // allocate memory for encoding           
        pki = (PCERT_PUBLIC_KEY_INFO)xmalloc(pkiLen);

        // export public key
        if (CryptExportPublicKeyInfo(prov, AT_KEYEXCHANGE, 
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 
            pki, &pkiLen))
        {             
          // convert to DER format
          if (CryptEncodeObjectEx(
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            X509_PUBLIC_KEY_INFO, pki, 0, 
            NULL, NULL, &derLen))
        }
      }
    } else {
      if (CryptExportPKCS8(rsa->prov, AT_KEYEXCHANGE, 
          szOID_RSA_RSA, 0, NULL, NULL, &pkiLen))
      {
        pki = (PCRYPT_PRIVATE_KEY_INFO)xmalloc(pkiLen);
      
        if (pki != NULL)
        {
          CryptExportPKCS8(rsa->prov, AT_KEYEXCHANGE, 
            szOID_RSA_RSA, 0x8000, NULL, 
            (PBYTE)pki, &pkiLen);
        }
      }
    }  
}

