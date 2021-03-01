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
#include <openssl/x509v3.h>
#include <openssl/pkcs12.h>
#include <openssl/engine.h>
#include <openssl/conf.h>
#include <openssl/crypto.h>
#include <main.h>

extern char *heapStringPtr;

EVP_PKEY *readECPrivateKey(int keyPointer)
{
    char *keyString = (char *)keyPointer;
    BIO *keyBio = BIO_new(BIO_s_secmem());
    BIO_write(keyBio, keyString, strlen(keyString));
    EVP_PKEY *privateKey = NULL;
    if (!PEM_read_bio_PrivateKey(keyBio, &privateKey, NULL, NULL)) //TODO password
    {
        throwError();
    }

    return privateKey;
}

void add_req_ext(X509_REQ *x509_req, int nidReqPointer)
{

    STACK_OF(X509_EXTENSION) *x509_req_stack = X509_REQ_get_extensions(x509_req);
    int num_ext = sk_X509_EXTENSION_num(x509_req_stack);
    printf("NUM EXT: ======>%i\n", num_ext);
    for (int i = 0; i < num_ext; i++)
    {

        X509_EXTENSION *ex = sk_X509_EXTENSION_value(x509_req_stack, i);
        ASN1_OBJECT *obj = X509_EXTENSION_get_object(ex);

        BIO *ext_bio = BIO_new(BIO_s_mem());
        if (!X509V3_EXT_print(ext_bio, ex, 0, 0))
        {
        }
        BUF_MEM *bptr;
        BIO_get_mem_ptr(ext_bio, &bptr);
        BIO_set_close(ext_bio, BIO_NOCLOSE);

        // remove newlines
        int lastchar = bptr->length;
        if (lastchar > 1 && (bptr->data[lastchar - 1] == '\n' || bptr->data[lastchar - 1] == '\r'))
        {
            bptr->data[lastchar - 1] = (char)0;
        }
        if (lastchar > 0 && (bptr->data[lastchar] == '\n' || bptr->data[lastchar] == '\r'))
        {
            bptr->data[lastchar] = (char)0;
        }

        BIO_free(ext_bio);

        unsigned nid = OBJ_obj2nid(obj);
        if (nid == NID_undef)
        {
            // no lookup found for the provided OID so nid came back as undefined.
            char extname[num_ext];
            OBJ_obj2txt(extname, num_ext, (const ASN1_OBJECT *)obj, 1);
            printf("extension name is %s\n", extname);
        }
        else
        {
            // the OID translated to a NID which implies that the OID has a known sn/ln
            const char *c_ext_name = OBJ_nid2ln(nid);
            printf("extension name is %s\n", c_ext_name);
        }

        printf("extension length is %zu\n", bptr->length);
        printf("extension value is %s\n", bptr->data);
    }
}

int add_exts(X509 *cert, int nidPointer)
{
    uint32_t *nidp;
    uint32_t *currn = (uint32_t *)nidPointer;

    while (*currn)
    {
        if ((((int)currn - nidPointer) % (sizeof(uint32_t) * 2)) == 0)
        {
            nidp = currn;
        }
        else
        {
            X509_EXTENSION *ex;
            X509V3_CTX ctx;
            X509V3_set_ctx_nodb(&ctx);
            X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);
            ex = X509V3_EXT_conf_nid(NULL, &ctx, *nidp, (char *)*currn);
            if (ex)
            {
                X509_add_ext(cert, ex, -1);
            }
            X509_EXTENSION_free(ex);
        }
        currn++;
    }
    return 1;
}

int add_ext_stack(STACK_OF(X509_EXTENSION) * sk, int nid, char *value)
{
    X509_EXTENSION *ex;
    ex = X509V3_EXT_conf_nid(NULL, NULL, nid, value);
    if (!ex)
        return 0;
    sk_X509_EXTENSION_push(sk, ex);

    return 1;
}

int add_ext_stacks(X509_REQ *x509_req, STACK_OF(X509_EXTENSION) * exts_req, int nidPointer)
{

    uint32_t *nidp;
    uint32_t *currn = (uint32_t *)nidPointer;

    while (*currn)
    {
        if ((((int)currn - nidPointer) % (sizeof(uint32_t) * 2)) == 0)
        {
            nidp = currn;
        }
        else
        {
            X509_EXTENSION *ex;
            add_ext_stack(exts_req, *nidp, (char *)*currn);
        }
        currn++;
    }
    return 1;
}

int generateX509Certificate(X509 *x509)
{
    BIO *x509Bio = BIO_new(BIO_s_secmem());

    PEM_write_bio_X509(x509Bio, x509);
    unsigned char *x509PEMString;
    BIO_read(x509Bio, x509PEMString, -1);
    int len = BIO_get_mem_data(x509Bio, &x509PEMString);
    heapStringPtr = malloc(len + 1);
    heapStringPtr[len] = '\0';
    BIO_read(x509Bio, heapStringPtr, len);
    BIO_free(x509Bio);
    return 0;
}

int generateX509CertificateRequest(X509_REQ *x509_req)
{
    BIO *x509Bio_req = BIO_new(BIO_s_secmem());
    PEM_write_bio_X509_REQ(x509Bio_req, x509_req);
    unsigned char *x509REQPEMString;
    BIO_read(x509Bio_req, x509REQPEMString, -1);
    int len = BIO_get_mem_data(x509Bio_req, &x509REQPEMString);
    heapStringPtr = malloc(len + 1);
    heapStringPtr[len] = '\0';
    BIO_read(x509Bio_req, heapStringPtr, len);
    BIO_free(x509Bio_req);
    return 0;
}

int generatePKCS12Bundle(X509 *x509, struct keystruct certStruct, char *friendlyName, X509 *x509_ca)
{
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    BIO *pkcs12Bio = BIO_new(BIO_s_secmem());
    PKCS12 *pkcs12bundle;
    STACK_OF(X509) * cacertstack;
    if ((cacertstack = sk_X509_new_null()) == NULL)
        throwError();
    //TODO ADD CA CERT HERE!!!!
    if (!sk_X509_push(cacertstack, x509))
        throwError();

    if ((pkcs12bundle = PKCS12_new()) == NULL)
        throwError();

    /* values of zero use the openssl default values */
    pkcs12bundle = PKCS12_create(
        certStruct.password ? certStruct.password : NULL, // certbundle access password
        friendlyName,                                     // friendly certname
        certStruct.evp_keyobject,                         // the certificate private key
        x509,                                             // the main certificate
        cacertstack,                                      // stack of CA cert chain
        0,                                                // int nid_key (default 3DES)
        0,                                                // int nid_cert (40bitRC2)
        0,                                                // int iter (default 2048)
        0,                                                // int mac_iter (default 1)
        0                                                 // int keytype (default no flag)
    );
    if (pkcs12bundle == NULL)
        throwError();

    if (!i2d_PKCS12_bio(pkcs12Bio, pkcs12bundle))
        throwError();
    unsigned char *pkcs12PEMString;
    BIO_read(pkcs12Bio, pkcs12PEMString, -1);
    int len = BIO_get_mem_data(pkcs12Bio, &pkcs12PEMString);
    heapStringPtr = malloc(len + 1);
    heapStringPtr[len] = '\0';
    BIO_read(pkcs12Bio, heapStringPtr, len);
    char *hexbuf = OPENSSL_buf2hexstr((const unsigned char *)heapStringPtr, len);
    free(heapStringPtr);
    heapStringPtr = hexbuf;
    heapStringPtr[strlen(hexbuf)] = '\0';
    sk_X509_free(cacertstack);
    BIO_free(pkcs12Bio);
    return 1;
}

int set_serial(X509 *x509, char *hexSerial)
{
    BN_CTX *pub_ctx;
    pub_ctx = BN_CTX_new();
    BIGNUM *serial_bn = BN_new();
    BN_hex2bn(&serial_bn, (const char *)hexSerial);

    ASN1_INTEGER *serial = ASN1_INTEGER_new();
    BN_to_ASN1_INTEGER(serial_bn, serial);
    X509_set_serialNumber(x509, serial);
    ASN1_INTEGER_free(serial);

    BN_free(serial_bn);

    return 1;
}

X509 *readCertificate(int certPointer)
{
    char *certString = (char *)certPointer;
    BIO *x509Bio = BIO_new(BIO_s_secmem());
    BIO_write(x509Bio, certString, strlen(certString));
    X509 *x509 = X509_new();
    if (!PEM_read_bio_X509(x509Bio, &x509, NULL, NULL))
    {
        throwError();
    }
    return x509;
}

X509_REQ *readCertificateSigningRequest(int csrPointer)
{
    char *csrString = (char *)csrPointer;
    BIO *x509Bio_req = BIO_new(BIO_s_secmem());
    BIO_write(x509Bio_req, csrString, strlen(csrString));
    X509_REQ *x509_req = X509_REQ_new();
    if (!PEM_read_bio_X509_REQ(x509Bio_req, &x509_req, NULL, NULL))
    {
        throwError();
    }
    return x509_req;
}

X509 *genCert(
    int notBefore,
    int notAfter,
    int version,
    int idPointer,
    int nidArrayPointer)
{

    X509 *x509 = X509_new();

    X509_gmtime_adj(X509_get_notBefore(x509), notBefore);
    X509_gmtime_adj(X509_get_notAfter(x509), notAfter);
    X509_set_version(x509, version);

    if (!set_serial(x509, (char *)idPointer))
    {
        throwError();
    }

    add_exts(x509, nidArrayPointer);
    return x509;
}

int createCertificate(
    int curve,
    int compressed,
    int password,
    int notBefore,
    int notAfter,
    int version,
    int keyPointer, /*TODO Pass In Hex, PEM, p12*/
    int namePointer,
    int issuerPointer,
    int idPointer,
    int friendlyNamePointer,
    int csrPointer,
    int nidArrayPointer,
    int outformat,
    int caPEMPointer,
    int caPointer)
{

    free(heapStringPtr);

    X509_REQ *x509_req = csrPointer ? readCertificateSigningRequest(csrPointer) : NULL;
    X509 *x509_ca = caPointer ? readCertificate(caPointer) : NULL;
    struct keystruct certStruct;

    if (keyPointer && curve)
    //Passing in params to create key in single step
    {
        certStruct = hexToEVP((char *)keyPointer, curve, 0, compressed, (char *)password);
    }
    else if (caPEMPointer)
    {
        certStruct.evp_keyobject = readECPrivateKey(caPEMPointer);
        certStruct.password = (char *)password;
    }
    else
    {
        throwError();
    }

    X509 *x509 = genCert(notBefore,
                         notAfter,
                         version,
                         idPointer,
                         nidArrayPointer);
    /*Set Public Key*/
    if (x509_req)
    {
        X509_set_pubkey(x509, X509_REQ_get_pubkey(x509_req));
    }
    else
    {
        X509_set_pubkey(x509, certStruct.evp_keyobject);
    }
    /*Set Issuer and Name*/
    if (x509_req)
    {
        X509_set_subject_name(x509, X509_REQ_get_subject_name(x509_req));
    }
    else
    {
        str2Name(namePointer, X509_get_subject_name(x509));
    }

    str2Name(issuerPointer, X509_get_issuer_name(x509));

    //Always have to sign certificate to start, can resign
    int md_nid;
    const EVP_MD *md;

    if (EVP_PKEY_get_default_digest_nid(certStruct.evp_keyobject, &md_nid) <= 0)
        throwError();

    md = (md_nid == NID_undef)
             ? EVP_md_null()
             : EVP_get_digestbynid(md_nid);
    if (X509_sign(x509, certStruct.evp_keyobject, md) <= 0)
        throwError();

    if (outformat == NID_x509Certificate)
    {
        generateX509Certificate(x509);
    }
    else if (outformat == NID_certBag)
    {
        generatePKCS12Bundle(x509, certStruct, (char *)friendlyNamePointer, x509_ca);
    }
    return (int)heapStringPtr;
}

int createCertificateSigningRequest(
    int curve,
    int compressed,
    int password,
    int version,
    int keyPointer,
    int namePointer,
    int idPointer,
    int nidArrayPointer)
{
    free(heapStringPtr);

    struct keystruct certStruct = hexToEVP((char *)keyPointer, curve, 0, compressed, NULL);
    X509_REQ *x509_req = X509_REQ_new();
    X509_REQ_set_version(x509_req, version);
    X509_REQ_set_pubkey(x509_req, certStruct.evp_keyobject);
    STACK_OF(X509_EXTENSION) *exts_req = sk_X509_EXTENSION_new_null();
    add_ext_stacks(x509_req, exts_req, nidArrayPointer);
    X509_REQ_add_extensions(x509_req, exts_req);
    str2Name(namePointer, X509_REQ_get_subject_name(x509_req));

    int md_nid;
    const EVP_MD *md;
    if (EVP_PKEY_get_default_digest_nid(certStruct.evp_keyobject, &md_nid) <= 0)
        throwError();

    md = (md_nid == NID_undef)
             ? EVP_md_null()
             : EVP_get_digestbynid(md_nid);
    if (!X509_REQ_sign(x509_req, certStruct.evp_keyobject, md))
        throwError();

    generateX509CertificateRequest(x509_req);
    return (int)heapStringPtr;
}