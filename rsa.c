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
    HCRYPTPROV prov=0;
    RSA        *rsa=NULL;

    if (CryptAcquireContext(&prov,
        NULL, NULL, PROV_RSA_FULL,
        CRYPT_VERIFYCONTEXT | CRYPT_SILENT | CRYPT_MACHINE_KEYSET))
    {
      rsa = xmalloc(sizeof(RSA));
      if (rsa != NULL) {
        rsa->prov = prov;
      }
    }
    return rsa;
}

/**
 *
 * close CSP and release memory for RSA object
 *
 */
void rsa_close(RSA *rsa)
{
    if (rsa==NULL) return;

    // release private key
    if (rsa->privkey != 0) {
      CryptDestroyKey(rsa->privkey);
      rsa->privkey = 0;
    }

    // release public key
    if (rsa->pubkey != 0) {
      CryptDestroyKey(rsa->pubkey);
      rsa->pubkey = 0;
    }

    // release csp
    if (rsa->prov != 0) {
      CryptReleaseContext(rsa->prov, 0);
      rsa->prov = 0;
    }
    
    // release object
    xfree(rsa);
}

/**
 *
 * generate new key pair of keyLen-bits
 *
 */
int rsa_genkey(RSA* rsa, int keyLen)
{
    if (rsa==NULL) return -1;

    // release public
    if (rsa->pubkey != 0) {
      CryptDestroyKey(rsa->pubkey);
      rsa->pubkey = 0;
    }
      
    // release private
    if (rsa->privkey != 0) {
      CryptDestroyKey(rsa->privkey);
      rsa->privkey = 0;
    }

    // generate key pair for signing
    CryptGenKey(rsa->prov, CALG_RSA_SIGN,
      (keyLen << 16) | CRYPT_EXPORTABLE,
      &rsa->privkey);

    rsa->error = GetLastError();
    return rsa->error == ERROR_SUCCESS;
}

/**
 *
 * write binary to file encoded in PEM format
 *
 * ifile   : name of file to write PEM encoded key
 * pemType : type of key being saved
 * rsa     : RSA object with public and private keys
 *
 */
int rsa_write_pem(int pemType, 
    LPVOID data, DWORD dataLen, const char* ofile)
{
    const char *s, *e, *b64;
    FILE       *out;
    BOOL       ok=FALSE;

    if (pemType == RSA_PRIVATE_KEY) {
      s = "-----BEGIN PRIVATE KEY-----\n";
      e = "-----END PRIVATE KEY-----\n";
    } else if (pemType == RSA_PUBLIC_KEY) {
      s = "-----BEGIN PUBLIC KEY-----\n";
      e = "-----END PUBLIC KEY-----\n";
    } else if (pemType == RSA_SIGNATURE) {
      s = "-----BEGIN PGP SIGNATURE-----\n";
      e = "-----END PGP SIGNATURE-----\n";
    }

    b64 = bintob64(data, dataLen, CRYPT_STRING_NOCR);

    if (b64 != NULL) {
      out = fopen(ofile, "wb");

      if (out != NULL) {
        fwrite(s, strlen(s), 1, out);
        fwrite(b64, strlen(b64), 1, out);
        fwrite(e, strlen(e), 1, out);
        fclose(out);
        ok=TRUE;
      }
    }
    return ok;
}

/**
 *
 * read public or private key in PEM format
 *
 * ifile   : name of file to write PEM encoded key
 * pemType : type of key being saved
 * rsa     : RSA object with public and private keys
 *
 */
LPVOID rsa_read_pem(const char* ifile, PDWORD binLen) 
{
    FILE        *in;
    struct stat st;
    LPVOID      pem=NULL, bin=NULL;

    stat(ifile, &st);
    if (st.st_size==0) return NULL;

    // open PEM file
    in = fopen(ifile, "rb");

    if (in != NULL) {
      // allocate memory for data
      pem = xmalloc(st.st_size);
      if (pem != NULL) {
        // read data
        fread(pem, sizeof(char), st.st_size, in);
        bin = b64tobin(pem, strlen(pem), 
            CRYPT_STRING_BASE64HEADER, binLen); 
        xfree(pem);            
      }
      fclose(in);
    }
    return bin;
}

/**
 *
 * save public or private key to PEM format
 *
 * ifile   : name of file to write PEM encoded key
 * pemType : type of key being saved
 * rsa     : RSA object with public and private keys
 *
 */
int rsa_read_key(RSA* rsa, 
    const char* ifile, int pemType) 
{
    LPVOID                  derData, keyData;
    PCRYPT_PRIVATE_KEY_INFO pki = 0;
    DWORD                   pkiLen, derLen, keyLen;
    BOOL                    ok=FALSE;
    
    rsa->error = ERROR_SUCCESS;
    
    // decode base64 string ignoring headers
    derData = rsa_read_pem(ifile, &derLen);

    if (derData != NULL) {
      // decode DER
      // is it a public key?
      if (pemType == RSA_PUBLIC_KEY) {

        if (CryptDecodeObjectEx(
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            X509_PUBLIC_KEY_INFO, derData, derLen,
            CRYPT_DECODE_ALLOC_FLAG, NULL,
            &keyData, &keyLen))
        {

          // if decode ok, import it
          ok = CryptImportKey(rsa->prov, keyData, keyLen,
                   0, CRYPT_EXPORTABLE, &rsa->pubkey);

          // release allocated memory
          LocalFree(keyData);
        }
      } else {
        // convert the PKCS#8 data to private key info
        if (CryptDecodeObjectEx(
              X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
              PKCS_PRIVATE_KEY_INFO, derData, derLen,
              CRYPT_DECODE_ALLOC_FLAG,
              NULL, &pki, &pkiLen))
        {
          // then convert the private key to private key blob
          if (CryptDecodeObjectEx(
              X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
              PKCS_RSA_PRIVATE_KEY,
              pki->PrivateKey.pbData,
              pki->PrivateKey.cbData,
              CRYPT_DECODE_ALLOC_FLAG, NULL,
              &keyData, &keyLen))
          {  

            // if decode ok, import it
            ok = CryptImportKey(rsa->prov, keyData, keyLen,
                0, CRYPT_EXPORTABLE, &rsa->privkey);
                
            // release data
            LocalFree(keyData);
          }
          // release private key info
          LocalFree(pki);          
        }
      }
      xfree(derData);
    }
    return rsa->error == ERROR_SUCCESS;
}

/**
 *
 * save public or private key to PEM format
 *
 * ofile   : name of file to write PEM encoded key
 * pemType : type of key being saved
 * rsa     : RSA object with public and private keys
 *
 */
int rsa_write_key(RSA* rsa, 
    const char* ofile, int pemType) 
{
    DWORD  pkiLen, derLen;
    LPVOID pki, derData;

    if (pemType == RSA_PUBLIC_KEY)
    {
      if (CryptExportPublicKeyInfo(rsa->prov, AT_SIGNATURE,
          X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
          NULL, &pkiLen))
      {
        // allocate memory for encoding
        pki = xmalloc(pkiLen);

        // export public key
        if (CryptExportPublicKeyInfo(rsa->prov, AT_SIGNATURE,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            pki, &pkiLen))
        {
          // convert to DER format
          CryptEncodeObjectEx(
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            X509_PUBLIC_KEY_INFO, pki, 0,
            NULL, NULL, &derLen);

          derData = xmalloc(derLen);

          CryptEncodeObjectEx(
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            X509_PUBLIC_KEY_INFO, pki, 0,
            NULL, derData, &derLen);

          // write to PEM file
          rsa_write_pem(RSA_PUBLIC_KEY, derData, derLen, ofile);
          xfree(derData);
        } else printf ("\nCryptExportPublicKeyInfo");
      } else printf ("\nCryptExportPublicKeyInfo %i", GetLastError());
    } else {
      if (CryptExportPKCS8(rsa->prov, AT_SIGNATURE,
          szOID_RSA_RSA, 0, NULL, NULL, &pkiLen))
      {
        pki = xmalloc(pkiLen);

        if (pki != NULL)
        {
          CryptExportPKCS8(rsa->prov, AT_SIGNATURE,
            szOID_RSA_RSA, 0x8000, NULL,
            pki, &pkiLen);

          // write key to PEM file
          rsa_write_pem(RSA_PRIVATE_KEY, pki, pkiLen, ofile);
          xfree(pki);
        }
      }
    }
    return 1;
}

/**
 *
 *         calculate sha256 hash of file
 *
 * ifile : contains data to generate hash for
 * rsa   : RSA object with HCRYPTHASH object
 *
 */
int rsa_hash(RSA* rsa, const char* ifile)
{
    LPBYTE    data, p;
    ULONGLONG len;
    HANDLE    hFile, hMap;
    DWORD     r;

    rsa->error = ERROR_SUCCESS;
    
    // destroy hash object if already created
    if (rsa->hash != 0) {
      CryptDestroyHash(rsa->hash);
      rsa->hash = 0;
    }

    // try open the file for reading
    hFile = CreateFile (ifile, GENERIC_READ, FILE_SHARE_READ,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile != INVALID_HANDLE_VALUE) {
      // make sure we have something to hash
      GetFileSizeEx (hFile, (PLARGE_INTEGER)&len);
      if (len != 0)
      {        
        // create a file mapping handle
        hMap = CreateFileMapping (hFile, NULL,
            PAGE_READONLY, 0, 0, NULL);

        if (hMap != NULL) {
          // map a view of the file
          data = (LPBYTE)MapViewOfFile (hMap,
              FILE_MAP_READ, 0, 0, 0);

          if (data != NULL)
          {
            // create SHA-256 hash object
            if (CryptCreateHash (rsa->prov,
                CALG_SHA_256, 0, 0, &rsa->hash))
            {
              p = data;
              // while data available
              while (len)
              {
                r = (len < 8192) ? len : 8192;
                // hash input for every 8192 bytes or whatever remains
                if (!CryptHashData (rsa->hash, p, r, 0)) break;
                  
                len -= r;  // update length
                p   += r;  // update position in file
              }
            }
            UnmapViewOfFile ((LPCVOID)data);
          }
          CloseHandle (hMap);
        }        
      }
      CloseHandle (hFile);
    }
    return rsa->error == ERROR_SUCCESS;
}

/**
 *
 *          create a signature for file
 *
 * sfile  : where to write PEM encoded signature
 * ifile  : contains data to generate signature for
 * rsa    : RSA object with private key
 *
 */
int rsa_sign(RSA* rsa, 
    const char* ifile, const char* sfile)
{
    DWORD  sigLen=0;
    LPVOID sig;
    BOOL   ok=FALSE;
    
    // calculate sha256 hash for file 
    if (rsa_hash(rsa, ifile))
    {    
      // acquire length of signature
      if (CryptSignHash (rsa->hash, AT_SIGNATURE,
          NULL, 0, NULL, &sigLen))
      {
        sig = xmalloc (sigLen);
        if (sig != NULL)
        {
          // obtain signature
          if (CryptSignHash (rsa->hash, AT_SIGNATURE, 
              NULL, 0, sig, &sigLen))
          {
            // convert binary to PEM format and write to file
            rsa_write_pem(RSA_SIGNATURE, sig, sigLen, sfile);
            ok=TRUE;
          }
          xfree(sig);
        }
      } else printf ("cy %08X", GetLastError());
    } else printf ("rsa_hash");
    return ok;
}

/**
 *
 *         verify a signature using public key 
 *
 * sfile : file with signature encoded in PEM format
 * ifile : file with data to verify signature for
 * rsa   : RSA object with public key
 *
 */
int rsa_verify(RSA* rsa, 
    const char* ifile, const char* sfile)
{
    DWORD  sigLen;
    LPVOID sig;
    BOOL   ok=FALSE;
    
    // convert PEM data to binary
    sig = rsa_read_pem(sfile, &sigLen);
    
    if (sig != NULL)
    {
      // calculate sha256 hash of file 
      if (rsa_hash(rsa, ifile))
      {    
        // verify signature using public key
        ok = CryptVerifySignature (rsa->hash, sig, 
                    sigLen, rsa->pubkey, NULL, 0);  
      }
    }      
    return ok;            
}
