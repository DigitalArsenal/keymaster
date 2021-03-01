/* COPYRIGHT DIGITALARSENAL.IO INC. ALL RIGHTS RESERVED.
 * 
 * LICENSE: APACHE-2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/pkcs12.h>
#include <openssl/engine.h>
#include <openssl/conf.h>
#include <main.h>

char *heapStringPtr = 0;

int generate_PEM(struct keystruct convertStruct)
{

    BIO *pemBio = BIO_new(BIO_s_secmem());

    if (convertStruct.outtype == NID_X9_62_id_ecPublicKey)
    {
        if (!PEM_write_bio_PUBKEY(pemBio, convertStruct.evp_keyobject))
        {
            ERR_print_errors_fp(stderr);
            return -1;
        }
    }
    else if (convertStruct.outtype == NID_Private)
    {
        if (!PEM_write_bio_PrivateKey(
                pemBio,
                convertStruct.evp_keyobject,
                convertStruct.password ? EVP_aes_192_cbc() : NULL,
                NULL,
                0,
                0,
                convertStruct.password ? convertStruct.password : NULL))
        {
            ERR_print_errors_fp(stderr);
            return -1;
        }
    }

    unsigned char *privatePEM;
    BIO_read(pemBio, privatePEM, -1);
    int len = BIO_get_mem_data(pemBio, &privatePEM);
    heapStringPtr = malloc(len + 1);
    heapStringPtr[len] = '\0';
    BIO_read(pemBio, heapStringPtr, len);
    BIO_free(pemBio);
    return 0;
}

int generate_HEX(struct keystruct convertStruct)
{

    if (!convertStruct.EVP_ONLY)
    {
        EVP_PKEY_CTX *pkctx = EVP_PKEY_CTX_new(convertStruct.evp_keyobject, NULL);
        EC_KEY *EXT_EC = (EC_KEY *)EVP_PKEY_get1_EC_KEY(convertStruct.evp_keyobject);
        BN_CTX *key_ctx;
        key_ctx = BN_CTX_new();
        const EC_POINT *pub_key = EC_KEY_get0_public_key(EXT_EC);
        const BIGNUM *prv_bn_key = EC_KEY_get0_private_key(EXT_EC);
        if (convertStruct.outtype == NID_X9_62_id_ecPublicKey)
        {
            heapStringPtr = EC_POINT_point2hex(convertStruct.ecgroup, pub_key, convertStruct.compressed, key_ctx);
        }
        else if (convertStruct.outtype == NID_Private)
        {
            heapStringPtr = BN_bn2hex(prv_bn_key);
        }
        BN_CTX_free(key_ctx);
        EVP_PKEY_CTX_free(pkctx);
    }
    else
    {
        int (*keyFunc)(const EVP_PKEY *pkey, unsigned char *priv,
                       size_t *len);
        size_t size;
        if (convertStruct.outtype == NID_X9_62_id_ecPublicKey)
        {
            keyFunc = &EVP_PKEY_get_raw_public_key;
        }
        else if (convertStruct.outtype == NID_Private)
        {
            keyFunc = &EVP_PKEY_get_raw_private_key;
        }

        if (!(*keyFunc)(convertStruct.evp_keyobject, NULL, &size))
            return throwError();
        unsigned char *public_bytes = malloc(size);
        if (!(*keyFunc)(convertStruct.evp_keyobject, public_bytes, &size))
            return throwError();
        BIGNUM *pub_bn = BN_new();
        BN_bin2bn(public_bytes, 32, pub_bn);
        heapStringPtr = BN_bn2hex(pub_bn);
        free(public_bytes);
    }
    toLower(heapStringPtr);
    return 0;
}

struct keystruct hexToEVP(char *hex_private, int NID, int outtype, int compressed, char *password)
{
    bool EVP_ONLY = false;
    int EVP_TYPE = -1;
    int error = 0;
    switch (NID)
    {
    case EVP_PKEY_HMAC:
        EVP_ONLY = true;
        EVP_TYPE = EVP_PKEY_HMAC;
        break;
    case EVP_PKEY_POLY1305:
        EVP_ONLY = true;
        EVP_TYPE = EVP_PKEY_POLY1305;
        break;
    case EVP_PKEY_SIPHASH:
        EVP_ONLY = true;
        EVP_TYPE = EVP_PKEY_SIPHASH;
        break;
    case NID_X25519:
        EVP_ONLY = true;
        EVP_TYPE = EVP_PKEY_X25519;
        break;
    case NID_ED25519:
        EVP_ONLY = true;
        EVP_TYPE = EVP_PKEY_ED25519;
        break;
    case NID_X448:
        EVP_ONLY = true;
        EVP_TYPE = EVP_PKEY_X448;
        break;
    case NID_ED448:
        EVP_ONLY = true;
        EVP_TYPE = EVP_PKEY_ED448;
        break;
    }

    EVP_PKEY *evp_keyobject = NULL;
    EVP_PKEY_CTX *pkctx = EVP_PKEY_CTX_new(evp_keyobject, NULL);
    EC_GROUP *ecgroup = NULL;
    EC_KEY *ec_keypair = NULL;

    if (!EVP_ONLY)
    {
        ecgroup = EC_GROUP_new_by_curve_name(NID);
        evp_keyobject = EVP_PKEY_new();
        ec_keypair = EC_KEY_new_by_curve_name(NID);
        EVP_PKEY_set1_EC_KEY(evp_keyobject, ec_keypair);
        EC_KEY_set_group(ec_keypair, ecgroup);
        EC_KEY_set_asn1_flag(ec_keypair, OPENSSL_EC_NAMED_CURVE);
    }
    else
    {
        EVP_PKEY_set_type(evp_keyobject, EVP_TYPE);
    }

    /* IMPORT PRIVATE KEY AS HEX STRING */
    BIGNUM *bn_private = BN_new();
    BN_hex2bn(&bn_private, hex_private);
    if (!EVP_ONLY)
    {
        int SET_EC_PRIVATE = EC_KEY_set_private_key(ec_keypair, bn_private);
        if (1 != SET_EC_PRIVATE)
        {
            ERR_print_errors_fp(stderr);
            error = -1;
        }
    }
    else
    {
        unsigned char *private_bytes = malloc(32);
        int BIN_LEN = BN_bn2bin((const BIGNUM *)bn_private, private_bytes);
        evp_keyobject = EVP_PKEY_new_raw_private_key(EVP_TYPE, NULL, private_bytes, BN_num_bytes(bn_private));
        free(private_bytes);
    }

    if (!EVP_ONLY)
    {
        /* CREATE PUBLIC KEY BY DOING EC MULTIPLICATION*/
        BN_CTX *mul_ctx = BN_CTX_new();
        EC_POINT *pub_key = EC_POINT_new(ecgroup);
        const int MUL_SUCCESS = EC_POINT_mul(ecgroup, pub_key, bn_private, NULL, NULL, mul_ctx);
        BN_CTX_free(mul_ctx);

        if (1 != MUL_SUCCESS)
        {
            ERR_print_errors_fp(stderr);
            error = -1;
        }

        EC_KEY_set_public_key(ec_keypair, pub_key);
        EVP_PKEY_set1_EC_KEY(evp_keyobject, ec_keypair);
        EC_KEY_set_group(ec_keypair, ecgroup);
    }
    struct keystruct convertStruct = {evp_keyobject, NID, outtype, EVP_ONLY, ecgroup, compressed, password, error};
    return convertStruct;
}

int convertKey(int NID, long keyPointer, int outtype, int outformat, int compressed, int password)
{
    free(heapStringPtr);
    char *hex_private = (char *)keyPointer;

    struct keystruct convertStruct = hexToEVP(hex_private, NID, outtype, compressed, (char *)password);

    if (outformat == V_ASN1_BIT_STRING)
    {

        generate_HEX(convertStruct);
    }
    else if (outformat == PEM_TYPE_CLEAR || outformat == PEM_TYPE_ENCRYPTED)
    {
        generate_PEM(convertStruct);
    }

    return (int)heapStringPtr;
}

int cleanup()
{
    //FIPS_mode_set(0);
    CRYPTO_set_locking_callback(NULL);
    CRYPTO_set_id_callback(NULL);
    ENGINE_cleanup();
    CONF_modules_unload(1);
    ERR_free_strings();
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    return 0;
}
int main()
{
    //FIPS_mode_set(1);
    return 0;
}
