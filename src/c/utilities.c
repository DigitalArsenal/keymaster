#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <main.h>

char *trim_space(char *str)
{
    if (strlen(str))
    {
        char *end;
        while (isspace(*str))
        {
            str = str + 1;
        }
        if (strlen(str))
        {
            end = str + strlen(str) - 1;
            while (end > str && isspace(*end))
            {
                end = end - 1;
            }
            *(end + 1) = '\0';
        }
    }
    return str;
}

int throwError()
{
    ERR_print_errors_fp(stderr);
    return -1;
}

uint8_t *createBuffer(int bsize)
{
    return malloc(bsize);
}

void destroyBuffer(uint8_t *p)
{
    free(p);
}

void toCase(char *str, int (*f)(int))
{
    int slen = strlen(str);
    for (int i = 0; i < slen; i++)
    {
        char *np = (char *)((long)str + i);
        *np = f(*np);
    }
}

char *toLower(char *str)
{
    toCase(str, tolower);
    return str;
}

char *toUpper(char *str)
{
    toCase(str, toupper);
    return str;
}

X509_NAME *str2Name(int namePointer, X509_NAME *name)
{
    char *nameString = (char *)namePointer;
    const char c[1] = ",";
    const char e[1] = "=";
    char *cE, *eE;
    char *cToken = strtok_r(nameString, c, &cE);

    while (cToken != NULL)
    {
        char *eToken = strtok_r(cToken, e, &eE);
        while (eToken != NULL)
        {
            eToken = strtok_r(NULL, e, &eE);
            char *eL;
            if (!eToken)
            {
                X509_NAME_add_entry_by_txt(name, trim_space(cToken), MBSTRING_ASC, (unsigned char *)trim_space(eL), -1, -1, 0);
            }
            eL = eToken;
        }
        cToken = strtok_r(NULL, c, &cE);
    }
    return name;
}

int set_genString(GENERAL_NAMES *gens, int NID, char *value)
{
    GENERAL_NAME *genName = GENERAL_NAME_new();
    ASN1_IA5STRING *ia5 = ASN1_IA5STRING_new();
    ASN1_STRING_set(ia5, value, strlen(value));
    GENERAL_NAME_set0_value(genName, NID, ia5);
    if (sk_GENERAL_NAME_push(gens, genName) < 1)
        throwError();
    return 1;
}

bool isMatch(char *wordMatch, char *myWord)
{
    return strcmp(strstr(trim_space(toUpper(wordMatch)), myWord), myWord) == 0;
}