//
// Created by pete on 16.07.20.
//

#include <limits.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "parsing.h"
#include "containers.h"
#include "encoding.h"

bool parse_key_generic(uint8_t *key, const char *value, const unsigned key_len, const unsigned base64_len)
{
    if (!key_from_base64_generic(key, value, key_len, base64_len)) {
        fprintf(stderr, "Key is not the correct length or format: `%s'\n", value);
        memset(key, 0, key_len);
        return false;
    }
    return true;
}

bool parse_key(uint8_t *key, const char *value)
{
    return parse_key_generic(key, value, WG_KEY_LEN, WG_KEY_LEN_BASE64);
}

bool parse_keyfile_generic(uint8_t *key, const char *path, const unsigned key_len, const unsigned base64_len)
{
    FILE *f;
    int c;
    char dst[base64_len];
    bool ret = false;

    f = fopen(path, "r");
    if (!f) {
        perror("fopen");
        return false;
    }

    if (fread(dst, base64_len - 1, 1, f) != 1) {
        /* If we're at the end and we didn't read anything, we're /dev/null or an empty file. */
        if (!ferror(f) && feof(f) && !ftell(f)) {
            memset(key, 0, key_len);
            ret = true;
            goto out;
        }

        fprintf(stderr, "Invalid length key in key file\n");
        goto out;
    }
    dst[base64_len - 1] = '\0';

    while ((c = getc(f)) != EOF) {
        if (!isspace(c)) {
            fprintf(stderr, "Found trailing character in key file: `%c'\n", c);
            goto out;
        }
    }
    if (ferror(f) && errno) {
        perror("getc");
        goto out;
    }
    ret = parse_key_generic(key, dst, key_len, base64_len);

    out:
    fclose(f);
    return ret;
}

bool parse_keyfile(uint8_t key[WG_KEY_LEN], const char *path)
{
    return parse_keyfile_generic(key, path, WG_KEY_LEN, WG_KEY_LEN_BASE64);
}