#pragma once

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>

bool http_extract_key_from_valid_headers(char *headers, unsigned char *key);
char * http_build_answer_handshake(unsigned char *accepted_key);
