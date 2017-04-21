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
        CRYPT_VERIFYCONTEXT | CRYPT_SILENT))
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
    CryptReleaseContext(rsa->prov, 0);
    rsa->prov = 0;

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

    // release private key if already created
    if (rsa->privkey != 0) {
      CryptDestroyKey(rsa->privkey);
      rsa->privkey = 0;
      // release public aswell if required
      if (rsa->pubkey != 0) {
        CryptDestroyKey(rsa->pubkey);
        rsa->pubkey = 0;
      }
    }

    // generate key pair
    CryptGenKey(rsa->prov, CALG_RSA_KEYX,
      (keyLen << 16) | CRYPT_EXPORTABLE,
      &rsa->privkey);

    rsa->error = GetLastError();
    return rsa->error == ERROR_SUCCESS;
}

/**
 *
 * load and import public or pruvate key from PEM string
 *
 */
int rsa_load(RSA* rsa, const char* pem, int keyType) {
    LPVOID                  derData, keyData;
    PCRYPT_PRIVATE_KEY_INFO pki = 0;
    DWORD                   pkiLen, derLen, keyLen;

    // decode base64 string ignoring headers
    derData = b64tobin(pem, strlen(pem),
      CRYPT_STRING_BASE64HEADER, &derLen);

    if (derData != NULL) {
      // decode DER
      // is it a public key?
      if (keyType == RSA_PUBLIC_KEY) {

        CryptDecodeObjectEx(
          X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
          X509_PUBLIC_KEY_INFO, derData, derLen,
          CRYPT_DECODE_ALLOC_FLAG, NULL,
          &keyData, &keyLen);

        // if decode ok, import it
        CryptImportKey(rsa->prov, keyData, keyLen,
            0, CRYPT_EXPORTABLE, &rsa->pubkey);

        // release allocated memory
        LocalFree(keyData);
      } else {
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
            &keyData, &keyLen);

          // if decode ok, import it
          CryptImportKey(rsa->prov, keyData, keyLen,
              0, CRYPT_EXPORTABLE, &rsa->privkey);

          // release data
          LocalFree(keyData);
          LocalFree(pki);
        }
      }
      xfree(derData);
    }
    return rsa->error == ERROR_SUCCESS;
}

/**
 *
 * load public or private key from PEM file
 *
 */
int rsa_load_file(RSA* rsa, const char* pem, int keyType) {
    FILE        *in;
    struct stat st;
    LPVOID      pemData;
    size_t      size;

    if (rsa==NULL) return -1;
    if (pem==NULL) return -1;

    if (keyType!=RSA_PUBLIC_KEY &&
        keyType!=RSA_PRIVATE_KEY) return -1;

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

const char sig_start[]     = "-----BEGIN PGP SIGNATURE-----\n";
const char sig_end[]       = "-----END PGP SIGNATURE-----\n";

void rsa_key2pem(RSA *rsa, const char *fname,
    LPVOID data, DWORD len, int pemType)
{
    const char *s;
    const char *e;
    FILE       *out;
    LPVOID     *b64;

    if (pemType == RSA_PRIVATE_KEY) {
      s = private_start;
      e = private_end;
    } else if (pemType == RSA_PUBLIC_KEY) {
      s = public_start;
      e = public_end;
    } else if (pemType == RSA_SIGNATURE) {
      s = sig_start;
      e = sig_end;
    }

    b64 = bintob64(data, len, CRYPT_STRING_NOCR);

    if (b64 != NULL) {
      out = fopen(fname, "wb");

      if (out != NULL) {
        fwrite(s, strlen(s), 1, out);
        fwrite(b64, strlen((const char*)b64), 1, out);
        fwrite(e, strlen(e), 1, out);
        fclose(out);
      }
    }
}

/**
 *
 * save public or private key to PEM format
 *
 */
int rsa_save_file(RSA* rsa, const char* pem, int keyType) {
    DWORD  pkiLen, derLen;
    LPVOID pki, derData;

    if (keyType == RSA_PUBLIC_KEY)
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
          rsa_key2pem(rsa, pem, derData, derLen, RSA_PUBLIC_KEY);
          xfree(derData);
        }
      }
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
          rsa_key2pem(rsa, pem, pki, pkiLen, RSA_PRIVATE_KEY);
          xfree(pki);
        }
      }
    }
    return 1;
}

/**
 *
 * calculate sha256 hash of file
 *
 */
int rsa_hash(RSA* rsa, const char *f)
{
    LPBYTE    data;
    ULONGLONG len;
    HANDLE    hFile, hMap;

    // destroy hash object if already created
    if (rsa->hash != 0) {
      CryptDestroyHash(rsa->hash);
      rsa->hash = 0;
    }

    // try open the file
    hFile = CreateFile (f, GENERIC_READ, FILE_SHARE_READ,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile != INVALID_HANDLE_VALUE) {
      // create a file mapping handle
      hMap = CreateFileMapping (hFile, NULL,
          PAGE_READONLY, 0, 0, NULL);

      if (hMap != NULL) {
        // map a view of the file
        data = (LPBYTE)MapViewOfFile (hMap,
            FILE_MAP_READ, 0, 0, 0);

        if (data != NULL)
        {
          // obtain length
          GetFileSizeEx (hFile, (PLARGE_INTEGER)&len);

          // create hash object
          if (CryptCreateHash (rsa->prov,
              CALG_SHA_256, 0, 0, &rsa->hash))
          {
            // hash contents of file
            while (len)
            {
              // hash input for every 8192 bytes or whatever remains
              if (!CryptHashData (rsa->hash, data,
                  len<8192?len:8192, 0)) break;
                  
              len -= 8192;
            }
          }
          UnmapViewOfFile ((LPCVOID)data);
        }
        CloseHandle (hMap);
      }
      CloseHandle (hFile);
    }
    return rsa->error == ERROR_SUCCESS;
}

/**
 *
 * create a signature for file using private key
 *
 */
int rsa_sign(RSA* rsa, const char *in, const char *out)
{
    DWORD  sigLen;
    LPVOID sig;

    // calculate sha256 hash for file 
    rsa_hash(rsa, in);
    
    // acquire length of signature
    if (CryptSignHash (rsa->hash, AT_SIGNATURE,
        NULL, 0, NULL, &sigLen))
    {
      sig = xmalloc (sigLen);
      // obtain signature
      if (CryptSignHash (rsa->hash, AT_SIGNATURE, NULL, 0, sig, &sigLen))
      {
        // encode with base64 and write to file
      }
    }
}

/**
 *
 * verify a signature using public key 
 *
 */
int rsa_verify(RSA* rsa, const char *f, const char *s)
{
    DWORD  sigLen;
    LPVOID sig;
    BOOL   ok=FALSE;
    
    // convert signature to binary
    sig = rsa_read_pem(rsa, s, &sigLen);
    
    // calculate sha256 hash for file 
    rsa_hash(rsa, f);
    
    // verify using public key
    ok = CryptVerifySignature (rsa->hash, sig, 
                sigLen, rsa->pubkey, NULL, 0);                
    return ok;            
}
