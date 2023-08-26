//#include <stdio.h>
#include <inttypes.h>
#include <errno.h>

#define main kr_main
#include "../src/kr.c"
#undef main

#undef PASSWORD_H // use test shims.
#include "utils.h"
#include "platform.h"
#include "vectors.h"

#define MAX_FILE_SIZE 128 << 10

#define OK  GREEN "OK" RESET
#define FAILED  RED "FAILED" RESET

enum keytype {
    KEY_PROTECTED,
    KEY_UNPROTECTED
};

static const char *kt_name[] = {
    [KEY_PROTECTED] = "protected key",
    [KEY_UNPROTECTED] = "unprotected key",
};

// File paths used in the tests.
static char *NO_RIGHTS_FILENAME = "/root/key";
static char *NOT_EXIST_FILENAME = "/dev/shm/wrong";
static char *KEY_FILENAME = "/dev/shm/key";
static char *IN_FILENAME = "/dev/shm/in";
static char *ENC_FILENAME = "/dev/shm/enc";
static char *DEC_FILENAME = "/dev/shm/dec";

// Usage message string.
static const char *usage_text = "usage [-v] [seed]\n"
    "where -v is for verbose testing, and [seed] for the RNG seed\n"; 

int LOOPSIZE = 3;

// Generate a string of the form: '-pXXX' where XXX is a random string.
static inline void make_password_arg(char *password, size_t len)
{
    password[0] = '-';
    password[1] = 'p';
    for (size_t i = 2; i < len; ++i) {
        password[i] = 'A' + (rand64() % 26);
    }
    password[len] = '\0';
}

// Unit-test get_passphrase

static int u_get_passphrase(void)
{
    uint8_t passphrase[MAXPASS];
    enum error err = ERR_OK;
    int status = 0;
    int len = 0;

    // Read fail
    FAIL_PASSWORD(1);
    err = get_passphrase(passphrase, MAXPASS, &len, MODE_NONE);
    status |= (err != ERR_PASS_READ_FAIL);

    // Pass too big
    BIG_PASSWORD(1);
    err = get_passphrase(passphrase, MAXPASS, &len, MODE_NONE);
    status |= (err != ERR_PASS_TOO_BIG);

    // mode == MODE_NONE. Password length <= MAXPASS
    err = get_passphrase(passphrase, MAXPASS, &len, MODE_NONE);
    status |= (err != ERR_OK);

    // mode == MODE_ENCRYPT (confirmation asked)
    // 1) Same password repeated twice
    REPEAT_PASSWORD(2);
    err = get_passphrase(passphrase, MAXPASS, &len, MODE_ENCRYPT);
    status |= (err != ERR_OK);
    // 2) Password not repeated twice
    REPEAT_PASSWORD(0);
    err = get_passphrase(passphrase, MAXPASS, &len, MODE_ENCRYPT);
    status |= (err != ERR_PASS_NOT_MATCH);

    // mode == MODE_DECRYPT (no confirmation needed)
    REPEAT_PASSWORD(0);
    err = get_passphrase(passphrase, MAXPASS, &len, MODE_DECRYPT);
    status |= (err != ERR_OK);

    // mode == MODE_KEYGEN (no confirmation needed)
    // 1) Same password repeated twice
    REPEAT_PASSWORD(2);
    err = get_passphrase(passphrase, MAXPASS, &len, MODE_KEYGEN);
    status |= (err != ERR_OK);
    // 2) Password not repeated twice
    REPEAT_PASSWORD(0);
    err = get_passphrase(passphrase, MAXPASS, &len, MODE_KEYGEN);
    status |= (err != ERR_PASS_NOT_MATCH);
    
    // mode == MODE_KEYEDIT
    // 1) Same password repeated twice (confirmation asked)
    REPEAT_PASSWORD(2);
    err = get_passphrase(passphrase, MAXPASS, &len, MODE_KEYEDIT);
    status |= (err != ERR_OK);
    // 2 Empty password. (no confirmation needed)
    EMPTY_PASSWORD(1);
    err = get_passphrase(passphrase, MAXPASS, &len, MODE_KEYEDIT);
    status |= (err != ERR_OK);
    // 2) Password not repeated twice (no confirmation needed)
    REPEAT_PASSWORD(0);
    err = get_passphrase(passphrase, MAXPASS, &len, MODE_KEYEDIT);
    status |= (err != ERR_PASS_NOT_MATCH);

    printf("%s: get_passphrase\n", status != 0 ? FAILED: OK);

    return status;
}

// Test if written key is well-read
static int p_read_write_key(enum keytype kt)
{
    int status = 0;
    enum error err = ERR_OK;
    uint8_t kfdata[KEYFILE_SIZE - 1]; //wrong on purpose

    uint8_t key[KEY_SIZE];
    uint8_t read_key[KEY_SIZE];

    // No right to keyfile => error
    fillrand(key, KEY_SIZE);
    FILE *kf = fopen(NO_RIGHTS_FILENAME, "wb");
    err = read_keyfile(kf, key);
    status |= (err != ERR_INPUT_FILE);
    err = write_keyfile(kf, key, gen_key_config);
    status |= (err != ERR_OUTPUT_FILE);

    // No good keyfile size (trying to read short-sized i.e., truncated keyfile)
    kf = fopen(KEY_FILENAME, "wb");
    fillrand(kfdata, KEYFILE_SIZE-1);
    write_bytes(kf, kfdata, KEYFILE_SIZE-1);
    err = read_keyfile(kf, key);
    status |= (err != ERR_READ);

    for (int i = 0; i < LOOPSIZE; ++i) {

        if (kt == KEY_UNPROTECTED) {
            EMPTY_PASSWORD(1);
        } else {
            // Same password twice for write, once for read.
            REPEAT_PASSWORD(3);
        }

        fillrand(key, KEY_SIZE);
        FILE *kf = fopen(KEY_FILENAME, "wb");
        err = write_keyfile(kf, key, gen_key_config);
        status |= (err != ERR_OK);
        fclose(kf);
        kf = fopen(KEY_FILENAME, "rb");
        err = read_keyfile(kf, read_key);
        status |= (err != ERR_OK);
        // compare the read key with the written one.
        status |= memcmp(key, read_key, KEY_SIZE);
        fclose(kf);
        remove(KEY_FILENAME);
    }
    printf("%s: [[%s]] read(write(key)) == key\n", status != 0 ? FAILED: OK,
           kt_name[kt]);
    return status;
}

// Wrong password can't open protected key.
static int p_wrong_pass_cant_read_key(void)
{
    int status = 0;
    enum error err = ERR_OK;

    uint8_t key[KEY_SIZE];
    uint8_t read_key[KEY_SIZE];

    for (int i = 0; i < LOOPSIZE; ++i) {

        // Same password twice for write
        REPEAT_PASSWORD(2);

        fillrand(key, KEY_SIZE);
        FILE *kf = fopen(KEY_FILENAME, "wb");
        err = write_keyfile(kf, key, gen_key_config);
        status |= (err != ERR_OK);
        fclose(kf);
        kf = fopen(KEY_FILENAME, "rb");
        REPEAT_PASSWORD(0);
        err = read_keyfile(kf, read_key);
        status |= (err != ERR_INVALID);
        // compare the read key with the written one.
        status |= !memcmp(key, read_key, KEY_SIZE);
        fclose(kf);
        remove(KEY_FILENAME);
    }
    printf("%s: [[%s]] read(write(key)) != key\n", status != 0 ? FAILED: OK,
           "With wrong passphrase");
    return status;
}

// Test if decrypt(encrypt(x)) == x
static int p_encrypt_decrypt(void)
{
    int status = 0;
    enum error err = ERR_OK;
    uint8_t key[KEY_SIZE];
    uint8_t nonce[NONCE_SIZE];
    uint8_t  data[MAX_FILE_SIZE] = {0};
    uint8_t dec_buf[MAX_FILE_SIZE] = {0};
    uint64_t fsize = 0;

    fillrand(key, KEY_SIZE);
    fillrand(nonce, NONCE_SIZE);

    FILE *in_bad, *in_good, *out_bad, *out_good;

    // Edge cases: 1) Encryption
    // infile doesn't exist.
    in_bad = fopen(NOT_EXIST_FILENAME, "rb");
    out_good = fopen(NO_RIGHTS_FILENAME, "wb");
    err = encrypt(in_bad, out_good, key, nonce);
    status |= (err != ERR_INPUT_FILE);

    // infile can't read. bad mode.
    in_bad = fopen(IN_FILENAME, "wb");
    out_good = fopen(ENC_FILENAME, "wb");
    err = encrypt(in_bad, out_good, key, nonce);
    status |= (err != ERR_READ);
    fclose(in_bad);
    fclose(out_good);

    // outfile can't write. bad mode.
    in_good = fopen(IN_FILENAME, "rb");
    out_bad = fopen(ENC_FILENAME, "rb");
    err = encrypt(in_good, out_bad, key, nonce);
    status |= (err != ERR_WRITE);
    fclose(in_good);
    fclose(out_bad);

    // Edge cases: 2) Decryption
    // infile doesn't exist.
    in_bad = fopen(NOT_EXIST_FILENAME, "rb");
    out_good = fopen(NO_RIGHTS_FILENAME, "wb");
    err = decrypt(in_bad, out_good, key, nonce);
    status |= (err != ERR_INPUT_FILE);

    // infile can't read. bad mode.
    in_bad = fopen(IN_FILENAME, "wb");
    out_good = fopen(ENC_FILENAME, "wb");
    err = decrypt(in_bad, out_good, key, nonce);
    status |= (err != ERR_READ);
    fclose(in_bad);
    fclose(out_good);

    // outfile can't write. bad mode.
    // See Edge-case beow inside the loop.

    for (int i = 0; i < LOOPSIZE; ++i) {
        fsize = rand64() % MAX_FILE_SIZE;
        if (i == 0) {
            fsize = 0;
        }
        if (DEBUG) {
            printf(YELLOW "\tFile size:" BLUE " %lu bytes\n", fsize);
        }
        fillrand(data, fsize);
        fillrand(key, KEY_SIZE);
        fillrand(nonce, NONCE_SIZE);

        FILE *in = fopen(IN_FILENAME, "wb");
        FILE *enc = fopen(ENC_FILENAME, "wb");
        FILE *dec = fopen(DEC_FILENAME, "wb");

        write_bytes(in, data, fsize);
        fclose(in);
        in = fopen(IN_FILENAME, "rb");

        err = encrypt(in, enc, key, nonce);
        status |= (err != ERR_OK);
        fclose(enc);

        // Edge-case Test: decrypt to a read-only file.
        if (i == 1) {
            fclose(dec);
            dec = fopen(DEC_FILENAME, "rb");
            enc = fopen(ENC_FILENAME, "rb");
            err = decrypt(enc, dec, key, nonce);
            status |= (err != ERR_WRITE);
            fclose(dec);
            fclose(enc);
        }

        enc = fopen(ENC_FILENAME, "rb");
        dec = fopen(DEC_FILENAME, "wb");
        err = decrypt(enc, dec, key, nonce);
        status |= (err != ERR_OK);
        fclose(dec);

        dec = fopen(DEC_FILENAME, "rb");
        read_bytes(dec, dec_buf, fsize);

        status |= memcmp(data, dec_buf, fsize);

        fclose(in);
        fclose(enc);
        fclose(dec);
        remove(IN_FILENAME);
        remove(ENC_FILENAME);
        remove(DEC_FILENAME);
    }

    printf("%s: [[files]] decrypt(encrypt(x)) == x\n", status != 0 ? FAILED: OK);
    return status;
}

// Special cases of encrypt/decrypt
int u_encrypt_decrypt(void)
{
    int status = 0;
    enum error err = ERR_OK;
    uint8_t key[KEY_SIZE];
    uint8_t nonce[NONCE_SIZE];
    FILE *in, *out;

    fillrand(key, KEY_SIZE);
    fillrand(nonce, NONCE_SIZE);

    // Special cases of in and out.
    // Other cases are handled in p_encrypt_decrypt above.

    // 1) Can't encrypt inexistent file.
    in = fopen(NOT_EXIST_FILENAME, "rb");
    out = fopen("/dev/stdout", "wb");
    err = encrypt(in, out, key, nonce);
    status |= (err != ERR_INPUT_FILE);
    if (out) fclose(out);

    // 2) Can't encrypt file that can't be read.
    in = fopen("/dev/stdin", "rb");
    out = fopen(NO_RIGHTS_FILENAME, "wb");
    err = encrypt(in, out, key, nonce);
    status |= (err != ERR_OUTPUT_FILE);
    if (out) fclose(out);

    // 3) Can't decrypt inexistent file.
    in = fopen(NOT_EXIST_FILENAME, "rb");
    out = fopen("/dev/stdout", "wb");
    err = decrypt(in, out, key, nonce);
    status |= (err != ERR_INPUT_FILE);
    if (out) fclose(out);

    // 4) Can't decrypt file that can't be read.
    in = fopen("/dev/stdin", "rb");
    out = fopen(NO_RIGHTS_FILENAME, "wb");
    err = decrypt(in, out, key, nonce);
    status |= (err != ERR_OUTPUT_FILE);
    if (out) fclose(out);

    printf("%s: [[files (special cases)]] decrypt(encrypt(x)) == x\n",
           status != 0 ? FAILED: OK);

    return status;
}


// Test gen_key using the provided vector by Monocypher.
void gen_key_test(vector_reader *reader)
{
	crypto_argon2_config config;
	config.algorithm = load32_le(next_input(reader).buf);
	config.nb_blocks = load32_le(next_input(reader).buf);
	config.nb_passes = load32_le(next_input(reader).buf);
	config.nb_lanes  = load32_le(next_input(reader).buf);

	vector pass      = next_input(reader);
	vector salt      = next_input(reader);
	vector key       = next_input(reader);
	vector ad        = next_input(reader);
	vector out       = next_output(reader);

	crypto_argon2_inputs inputs;
	inputs.pass      = pass.buf;
	inputs.salt      = salt.buf;
	inputs.pass_size = (u32)pass.size;
	inputs.salt_size = (u32)salt.size;

	crypto_argon2_extras extras;
	extras.key       = key.buf;
	extras.ad        = ad.buf;
	extras.key_size  = (u32)key.size;
	extras.ad_size   = (u32)ad.size;

    gen_key(config, inputs, extras, out.size, out.buf);
}


// Test encrypt/decrypt using passphrases.
int p_password_enc_dec(void)
{
    enum error err = ERR_OK;
    int status = 0;
    uint8_t  data[MAX_FILE_SIZE] = {0};
    uint8_t  dec_buf[MAX_FILE_SIZE] = {0};
    uint64_t fsize = 0;
    char bigpass_arg[3+MAXPASS];

    // Password too big.
    make_password_arg(bigpass_arg, MAXPASS+2);
    char *argv_lp[7] = {"kr", "-e", bigpass_arg, IN_FILENAME, ENC_FILENAME, NULL};
    err = kr_main(7, argv_lp);
    status |= (err != ERR_PASS_TOO_BIG);

    // argvs to pass to kr for encryption and decryption.
    int argc = 6;
    char *argv_enc[6] = {"kr", "-e", "-p", IN_FILENAME, ENC_FILENAME, NULL};
    char *argv_dec[6] = {"kr", "-d", "-p", ENC_FILENAME, DEC_FILENAME, NULL};

    for (int i = 0; i < LOOPSIZE; ++i) {
        fsize = rand64() % MAX_FILE_SIZE;

        if (i == 0) {
            fsize = 0;
        }

        if (DEBUG) {
            printf(YELLOW "\tFile size:" BLUE " %lu bytes\n", fsize);
        }

        fillrand(data, fsize);

        FILE *in = fopen(IN_FILENAME, "wb");
        write_bytes(in, data, fsize);
        fclose(in);

        if (i < LOOPSIZE / 2) {
            REPEAT_PASSWORD(3);
            err = kr_main(argc, argv_enc);
            status |= (err != ERR_OK);

            err = kr_main(argc, argv_dec);
            status |= (err != ERR_OK);

            FILE *dec = fopen(DEC_FILENAME, "rb");
            read_bytes(dec, dec_buf, fsize);
            fclose(dec);
            status |= memcmp(data, dec_buf, fsize);
        } else {
            REPEAT_PASSWORD(2);
            err = kr_main(argc, argv_enc);
            status |= (err != ERR_OK);

            REPEAT_PASSWORD(0);
            err = kr_main(argc, argv_dec);
            status |= (err != ERR_INVALID);
        }

        remove(IN_FILENAME);
        remove(ENC_FILENAME);
        remove(DEC_FILENAME);
    }

    printf("%s: [[%s]] encrypt(decrypt(file)) == file\n",
           status != 0 ? FAILED: OK, "Passphrase-based operations");
    return status;
}


// Test encrypt/decrypt using keyfiles.
int p_keyfile_enc_dec(void)
{
    enum error err = ERR_OK;
    int status = 0;
    uint8_t  data[MAX_FILE_SIZE] = {0};
    uint8_t  dec_buf[MAX_FILE_SIZE] = {0};
    uint64_t fsize = 0;

    // Test with a keyfile that does not exist.
    char *argv_no_key[7] = {"kr", "-e", "-k", NOT_EXIST_FILENAME, IN_FILENAME, ENC_FILENAME, NULL};
    err = kr_main(7, argv_no_key);
    status |= (err != ERR_KEYFILE);

    int argc = 7;
    EMPTY_PASSWORD(2);
    err = kr_main(4, (char *[]){"kr", "-g", KEY_FILENAME, NULL});
    status |= (err != ERR_OK);


    fsize = rand64() % MAX_FILE_SIZE;
    fillrand(data, fsize);
    FILE *in = fopen(IN_FILENAME, "wb");
    write_bytes(in, data, fsize);
    fclose(in);

    // argvs to pass to kr for encryption and decryption.
    char *argv_enc[7] = {"kr", "-e", "-k", KEY_FILENAME, IN_FILENAME, ENC_FILENAME, NULL};
    char *argv_dec[7] = {"kr", "-d", "-k", KEY_FILENAME, ENC_FILENAME, DEC_FILENAME, NULL};

    err = kr_main(argc, argv_enc);
    status |= (err != ERR_OK);

    err = kr_main(argc, argv_dec);
    status |= (err != ERR_OK);

    FILE *dec = fopen(DEC_FILENAME, "rb");
    read_bytes(dec, dec_buf, fsize);
    fclose(dec);
    status |= memcmp(data, dec_buf, fsize);

    printf("%s: [[%s]] encrypt(decrypt(file)) == file\n",
           status != 0 ? FAILED: OK, "Keyfile-based operations");

    return status;
}

// Test random keyfiles generation
int u_gen_random_keyfile(void)
{
    int status = 0;
    enum error err = ERR_OK;

    freopen("/dev/null", "a+", stdout);
    freopen("/dev/null", "a+", stderr);


    // Generate a key to a filename that we can't access => exit code == 1
    err = kr_main(5, (char*[]){"kr", "-g", NO_RIGHTS_FILENAME, NULL});
    status |= (err != ERR_OUTPUT_FILE);

    // protected keyfile. passphrase == confirmed passphrase.
    for (int i = 0; i < LOOPSIZE; ++i) {
        REPEAT_PASSWORD(2);
        err = kr_main(5, (char*[]){"kr", "-g", KEY_FILENAME, NULL});
        status |= (err != ERR_OK);
    }

    // protected keyfile. passphrase != confirmed passphrase.
    for (int i = 0; i < LOOPSIZE; ++i) {
        REPEAT_PASSWORD(0);
        err = kr_main(5, (char*[]){"kr", "-g", KEY_FILENAME, NULL});
        status |= (err != ERR_PASS_NOT_MATCH);
    }

    // Unprotected keyfile.
    for (int i = 0; i < LOOPSIZE; ++i) {
        EMPTY_PASSWORD(2);
        err = kr_main(5, (char*[]){"kr", "-g", KEY_FILENAME, NULL});
        status |= (err != ERR_OK);
    }

    remove(KEY_FILENAME);

    freopen("/dev/tty", "w", stdout);

    printf("%s: random keyfiles generation\n", status != 0 ? FAILED: OK);
    return status;
}


// Test deterministic keyfiles generation
int u_gen_deterministic_keyfile(void)
{
    int status = 0;
    enum error err = ERR_OK;
    int argc = 6;
    char **argv;
    char uid[MAXUID];
    char uidl[MAXUID+1];

    fillrand(uid, rand64() % MAXUID);
    EMPTY_PASSWORD(2);
    argv = (char*[]){"kr", "-g", "-u", uid, "-pPASS", NO_RIGHTS_FILENAME, NULL};

    // Generate a key to a filename that we can't access => exit code == 1
    err = kr_main(argc, argv);
    status |= (err != ERR_OUTPUT_FILE);

    for (int i = 0; i < MAXUID; ++i) {
        uidl[i] = 'A' + (rand64() % 26);
    }
    uidl[MAXUID] = '\0';
    argv = (char*[]){"kr", "-g", "-u", uidl, "-pPASS", KEY_FILENAME, NULL};
    EMPTY_PASSWORD(2);
    err = kr_main(argc, argv);
    status |= (err != ERR_UID_TOO_BIG);

    // protected keyfile. passphrase == confirmed passphrase.
    for (int i = 0; i < LOOPSIZE; ++i) {
        REPEAT_PASSWORD(2);
        fillrand(uid, rand64() % MAXUID);
        argv = (char*[]){"kr", "-g", "-u", uid, "-pPASS", KEY_FILENAME, NULL};
        err = kr_main(argc, argv);
        status |= (err != ERR_OK);
    }

    // protected keyfile. passphrase != confirmed passphrase.
    for (int i = 0; i < LOOPSIZE; ++i) {
        REPEAT_PASSWORD(0);
        fillrand(uid, rand64() % MAXUID);
        argv = (char*[]){"kr", "-g", "-u", uid, "-pPASS",  KEY_FILENAME, NULL};
        err = kr_main(argc, argv);
        status |= (err != ERR_PASS_NOT_MATCH);
    }

    // Unprotected keyfile.
    for (int i = 0; i < LOOPSIZE; ++i) {
        EMPTY_PASSWORD(2);
        argv = (char*[]){"kr", "-g", "-u", uid, "-pPASS", KEY_FILENAME, NULL};
        err = kr_main(argc, argv);
        status |= (err != ERR_OK);
    }

    remove(KEY_FILENAME);

    printf("%s: deterministic keyfiles generation\n",
           status != 0 ? FAILED: OK);

    return status;
}

int test_usage_and_version(void)
{
    freopen("/dev/null", "a+", stdout);
    kr_main(3, (char*[]){"kr", "-V", NULL});
    kr_main(3, (char*[]){"kr", "-h", NULL});
    freopen("/dev/tty", "w", stdout);
    return 0;
}


int main(int argc, char **argv)
{

    errno = 0;
    int status = 0;
    DEBUG = 0;

    char *arg;
    int option;
    struct optparse options;

    (void) argc;
    optparse_init(&options, argv);
    while ((option = optparse(&options, "n:vh")) != -1) {
        switch (option) {
            case 'n':{
                char *p;
                LOOPSIZE = strtol(options.optarg, &p, 10);
                if (errno || *p) {
                    return 1;
                }
                if (LOOPSIZE < 1) {
                    return 1;
                }
            } break;
            case 'v':
                DEBUG = 1;
                break;
            case 'h':
            default:
                puts(usage_text);
                exit(0);
        }
    }

    if ((arg = optparse_arg(&options)) != NULL) {
        sscanf(arg, "%" PRIu64 "", &random_state);
    }

    printf("\nRandom seed: %" PRIu64 "\n", random_state);

    printf("\nUnit tests");
    printf("\n--------------------\n");
    status |= u_get_passphrase();
    status |= u_gen_random_keyfile();
    status |= u_gen_deterministic_keyfile();

    printf("\nTests against vectors");
    printf("\n--------------------\n");
    status |= vector_test(gen_key_test, "gen_key", nb_argon2_vectors, argon2_vectors);
    printf("%s: [[gen_key]] \n", status != 0 ? FAILED: OK);

    printf("\nProperty-based tests");
    printf("\n--------------------\n");

    status |= p_encrypt_decrypt();
    status |= u_encrypt_decrypt();
    status |= p_read_write_key(KEY_UNPROTECTED);
    status |= p_read_write_key(KEY_PROTECTED);
    status |= p_wrong_pass_cant_read_key();
    status |= p_password_enc_dec();
    status |= p_keyfile_enc_dec();
    status |= test_usage_and_version();

    printf("\n--------------------\n");
    printf("%s \n", (status == 0) ? GREEN"OK: "RESET"All tests passed"
           : RED"FAILED: "RESET"Some tests failed");
    return 0;
}


