#ifndef PASSWORD_H
#define PASSWORD_H

#include <stdint.h>

extern char shim[255];
extern int repeat;
extern int bigpass;
extern int emptypass;
extern int readfail;
extern int DEBUG;

#define YELLOW "\033[0;33m"
#define GREEN "\033[0;32m"
#define RED "\033[0;31m"
#define BLUE "\033[0;94m"
#define MAGENTA "\033[0;95m"
#define RESET "\033[0m"

#define REPEAT_PASSWORD(x) do { repeat = (x); } while (0);
#define EMPTY_PASSWORD(x) do { emptypass = (x); } while (0);
#define FAIL_PASSWORD(x) do { readfail = (x); } while (0);
#define BIG_PASSWORD(x) do { bigpass = 1; } while (0);

/* Set standard input and output to binary. */
void binary_stdio(void);

/* Fill buf with system entropy. */
int fillrand(void *buf, int len);

/* Display prompt then read zero-terminated, UTF-8 password.
 * Return password length with terminator, zero on input error, negative if
 * the buffer was too small.
 */
int read_password(uint8_t *buf, int len, char *prompt);

#endif
