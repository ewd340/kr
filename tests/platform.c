#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "utils.h"
#include "platform.h"
#include "passgen.h"

int repeat = 0;
int bigpass = 0;
int emptypass = 0;
int readfail = 0;
int DEBUG = 0;

void binary_stdio(void)
{
}

int fillrand(void *buf, int len)
{
    p_random(buf, len);
    return 0;
}

int read_password(uint8_t *buf, int len, char *prompt)
{
    static char shim[255];
    static int count = 0;
    static int amount = 0;
    int slen = 0;
    int nb_words = 1 + rand64() % 9;

    (void) len;
    (void) prompt;

    if (readfail) {
        readfail--;
        buf[0] = '\0';
        return 0;
    }

    if (bigpass) {
        bigpass = 0;
        buf[0] = '\0';
        return -1;
    }

    if (emptypass) {
        emptypass--;    
        buf[0] = '\0';
        return 1;
    }

    if (!repeat) {
        generate_passphrase(buf, nb_words);
        slen = strlen((char*) buf);
        memcpy(shim, buf, slen + 1);
    } else {
        if (!count) {
            count++;
            amount = repeat;
            generate_passphrase(buf, nb_words);
            slen = strlen((char*) buf);
            memcpy(shim, buf, slen + 1);
        } else {
            slen = strlen(shim);
            memcpy(buf, shim, slen + 1);
            count = (count + 1) % amount;
        } 
    }
    if (DEBUG) {
        printf( YELLOW "\t Typed passphrase:" BLUE " %s" RESET "\n", buf);
    }
    return slen;
}
