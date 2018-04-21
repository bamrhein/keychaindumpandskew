/*
 * Author: Brent Amrhein
 *
 * Description: Simple program that uses PBKDF2 to generate a 24-byte key from
 * an input string.
 *
 * Compiling: gcc pbkdf2.c -o pbkdf2
 *
 * Usage: ./pbkdf2 [string]
 */

#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

void print_usage()
{
    puts("USAGE:\n\t./pbkdf2 <string>\n");
}

// Writes a hex representation of the bytes in src to the dst buffer.
// The dst buffer must be at least len*2+1 bytes in size.
void hex_string(char *dst, char *src, size_t len) {
    int i;
    for (i = 0; i < len; ++i) {
        sprintf(dst+i*2, "%02x", (unsigned char)src[i]);
    }
}

void print_pbkdf2(const char *pass)
{
    unsigned char *salt = malloc(sizeof(char) * 20);
    RAND_bytes(salt, 20);

    /* string representation of salt */
    char s_salt[20*2+1];
    hex_string(s_salt, salt, 20);
    printf("salt: %s\n", s_salt);

    /* buffer for generated key */
    unsigned char *key = malloc(sizeof(char) * 24);

    PKCS5_PBKDF2_HMAC_SHA1(pass, // const char *pass
                           strlen(pass), // int passlen
                           salt, // unsigned char *salt
                           20, // int saltlen
                           1000, // int iter
                           24, // int keylen
                           key); // unsigned char *out

    /* string representation of key */
    char s_key[24*2+1];
    hex_string(s_key, key, 24);

    printf("Key derived from '%s': %s\n", pass, s_key);

    free(salt);
    free(key);
}

int main(int argc, char **argv)
{
    if (argc < 2 || argc > 2) {
        print_usage();
        return 0;
    }

    print_pbkdf2(argv[1]);
    return 0;
}
