#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/x509v3.h>

struct keystruct
{
    EVP_PKEY *evp_keyobject;
    int NID;
    int outtype;
    bool EVP_ONLY;
    EC_GROUP *ecgroup;
    int compressed;
    char *password;
    int error;
};

struct keystruct hexToEVP(char *hex_private, int NID, int outtype, int compressed, char *password);

char *trim_space(char *str);

int throwError();

uint8_t *createBuffer(int bsize);

void destroyBuffer(uint8_t *p);

char *toLower(char *str);

char *toUpper(char *str);

X509_NAME *str2Name(int namePointer, X509_NAME *name);

int set_genString(GENERAL_NAMES *gens, int NID, char *value);

int cleanup();