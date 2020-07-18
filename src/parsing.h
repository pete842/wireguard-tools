//
// Created by pete on 16.07.20.
//

#ifndef WIREGUARD_TOOLS_PARSING_H
#define WIREGUARD_TOOLS_PARSING_H

#include <stdint.h>
#include <stdbool.h>
#include "containers.h"

bool parse_key_generic(uint8_t *key, const char *value, const unsigned key_len, const unsigned base64_len);
bool parse_key(uint8_t *key, const char *value);
bool parse_keyfile_generic(uint8_t *key, const char *path, const unsigned key_len, const unsigned base64_len);
bool parse_keyfile(uint8_t key[WG_KEY_LEN], const char *path);


#endif //WIREGUARD_TOOLS_PARSING_H
