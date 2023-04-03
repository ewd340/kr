#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "platform.h"
#include "monocypher.h"

#define OPTPARSE_IMPLEMENTATION
#define OPTPARSE_API static
#include "optparse.h"

// Key file format
// ===============
//
// +----------------+------------+----------------------+-------------+
// |    24 bytes    |  16 bytes  |       1 byte         |   32 bytes  |
// +----------------+------------+----------------------+-------------+
// |  RANDOM NONCE  |     MAC    | PROTECTION | VERSION |     KEY     |
// +----------------+------------+----------------------+-------------+
//
// The most significant bit (farthest to the left) of the version byte
// is the key protection status. If it set to '1', then the key is
// protected using a passphrase. In this case, the key is decrypted
// using a passphrase given by the user and the random nonce, and is
// authenticated using the stored mac.
// Otherwise, the encryption/decryption key consists of the last 32 bytes
// of the file
//
// Encrypted File header
// =====================
//
// +----------------------------+--------------+-------------+
// |            24 bytes        |   1 byte     |  7 bytes    |
// +----------------------------+--------------+-------------+
// |          RANDOM NONCE      | FILE_VERSION |  RESERVED   |
// +----------------------------+--------------+-------------+
//
// When encrypting a file using a passphrase, we generate
// a key from a passphrase using Argon2, and we use the first
// ARGON_SALT_SIZE (16) bytes of the nonce as a salt.
//
// The FILE_VERSION is a single byte describing a file format.
// It does not have to be bumped on each version of the program,
// but mainly when big changes, that make backward compatibility
// very hard to maintain, occur.
//
// The 7 reserved bytes are, for the time being, unused.
// But, they could eventually be used in some future versions
// like to implement some new features or make the app handle
// backward compatibility issues.

#define PROG "kr"
#define PROG_VERSION "0.2" // The program's version.
#define FILE_VERSION 0 // Encrypted files format version.
#define KEYFILE_VERSION 0 // keyfiles format version.
#define KEY_SIZE 32
#define NONCE_SIZE 24 // Using XChaCha20.
#define MAC_SIZE 16
#define KEYFILE_SIZE NONCE_SIZE + MAC_SIZE + 1 + KEY_SIZE // See diagram above.
#define HEADER_SIZE NONCE_SIZE + 1 + 7 // See diagram above.
#define CHUNKLEN (128 << 10) - 16
#define MAXPASS 255
#define MAXUID 255
#define ARGON_SALT_SIZE 16
#define ARGON_NB_BLOCKS 100000
#define ARGON_NB_ITERATIONS 3
#define ARGON_NB_LANES 1

#define read_bytes(file, data, len) fread((data), 1, (len), (file))
#define write_bytes(file, data, len) fwrite((data), 1, (len), (file))

// Assign err_value to err (for return) and bail out to the bail label
// to securely clean sensitive data and exit.
#define BAIL(err_value) \
do { \
    err = (err_value); \
    goto bail; \
} while(0)

uint8_t END_TAG[4] = "LAST"; // Additional Data (tag) for the last chunk.

// Error codes used in this program.
enum error {
    ERR_OK,
    ERR_KEYFILE,
    ERR_INPUT_FILE,
    ERR_OUTPUT_FILE,
    ERR_READ,
    ERR_WRITE,
    ERR_INVALID,
    ERR_NO_RANDOM,
    ERR_NO_KEY,
    ERR_PASS_READ_FAIL,
    ERR_PASS_TOO_BIG,
    ERR_PASS_NOT_MATCH,
    ERR_VERSION_MISMATCH,
    ERR_UID,
    ERR_UID_TOO_BIG,
};

// Error messages associated with the error codes above.
static const char *errmsg[] = {
    [ERR_OK] = "All good",
    [ERR_KEYFILE] = "Failed to read keyfile",
    [ERR_INPUT_FILE] = "Failed to open input file",
    [ERR_OUTPUT_FILE] = "Failed to open output file",
    [ERR_READ] = "Input error",
    [ERR_WRITE] = "Output error",
    [ERR_INVALID] = "Wrong passphrase / bad input",
    [ERR_NO_RANDOM] = "Could not get enough entropy to function",
    [ERR_NO_KEY] = "Could not generate an encryption key",
    [ERR_PASS_READ_FAIL] = "Failed to read passphrase",
    [ERR_PASS_TOO_BIG] = "Passphrases must be less than 255 bytes",
    [ERR_PASS_NOT_MATCH] = "Passphrases do not match",
    [ERR_VERSION_MISMATCH] = "Version mismatch",
    [ERR_UID] = "UID missing",
    [ERR_UID_TOO_BIG] = "UID must be less than 255 bytes",
};

// Operation modes of the program.
enum operation {
    MODE_NONE,
    MODE_ENCRYPT,
    MODE_DECRYPT,
    MODE_KEYGEN,
    MODE_KEYEDIT,
};

// Configuration structure for the 'get_passphrase()' function.
// .prompt: the prompt (asking for a passphrase) to be displayed.
// .prompt_repeat: the prompt asking to type the passphrase again.
// .confirm: should the passphrase be typed again?
struct passphrase_config {
    char *prompt;
    char *prompt_repeat;
    int confirm;
};

// Various configurations for 'get_passphrase()' depending on the operation
// mode. This array (kind of a map) is used by 'get_passphrase()' to behave
// differently depending on the mode by which it is called.
static const struct passphrase_config passphrase_configs[] = {
    [MODE_NONE] = {
        .prompt = "",
        .prompt_repeat = "",
        .confirm = 0
    },
    [MODE_ENCRYPT] = {
        .prompt = "passphrase:",
        .prompt_repeat = "passphrase (repeat):",
        .confirm = 1
    },
    [MODE_DECRYPT] = {
        .prompt = "passphrase:",
        .prompt_repeat = "",
        .confirm = 0
    },
    [MODE_KEYGEN] = {
        .prompt = "passphrase:",
        .prompt_repeat = "passphrase (repeat):",
        .confirm = 1
    },
    [MODE_KEYEDIT] = {
        .prompt = "protection passphrase (empty for none):",
        .prompt_repeat = "protection passphrase (repeat):",
        .confirm = 1
    },
};

// Usage text displayed with the option '-h' (--help).
static const char *usage[] = {
"USAGE: kr [OPERATION] [OPTIONS] [in] [out]",
"",
"ARGUMENTS:",
"",
"   [in]       input file. If no input file is given, use STDIN.",
"   [out]      output file. If no output file is given, use STDOUT.",
"",
"OPERATION",
"",
"   -e | --encrypt            Encrypt [in] and put the output into [out].",
"",
"   -d | --decrypt            Decrypt [in] and put the output into [out].",
"",
"   -g | --generate           Generate a key and put it into [out].",
"                             The user can protect the generated key with",
"                             a passphrase.",
"",
"   -m | --edit <keyfile>     Edit <keyfile> by changing, removing,",
"                             or adding a protection passphrase.",
"",
"   -h | --help               Display this usage message.",
"",
"   -V | --version            Display the version information.",
"",
"OPTIONS",
"",
"   -k | --key=<keyfile>      Use the key in <keyfile> for operations.",
"",
"   -p | --passphrase=[pass]  Use the passphrase [pass] for for operations.",
"                             If the passphrase is not specified, prompt the",
"                             user to type it (Twice for encryption and",
"                             keyfile generation. Once for decryption).",
"",
"   -u | --uid=<uid>          Use <uid> for key generation (-g).",
"                             When used, the program will ask for a passphrase",
"                             in order to generate a deterministic key, i.e., ",
"                             the same key for the same <uid> and passphrase.",
"                             When <uid> is not given, the generated key will",
"                             be random.",
NULL
};

// Encrypt the 'in' file, using the key 'key' and the nonce 'nonce'
// and write encrypted chunks to the 'out' file.
static enum error encrypt(FILE *in, FILE *out, const uint8_t key[KEY_SIZE],
                          const uint8_t nonce[NONCE_SIZE])
{
    int eof = 0;
    enum error err = ERR_OK;

    uint8_t buf_in[CHUNKLEN];
    uint8_t buf_out[CHUNKLEN + MAC_SIZE];

    crypto_aead_ctx ctx;
    crypto_aead_init_x(&ctx, key, nonce);

    do {
        size_t len = read_bytes(in, buf_in, CHUNKLEN);

        if (!len && ferror(in)) {
            err = ERR_READ;
            break;
        }

        eof = feof(in);
        uint8_t *ad = (eof) ? END_TAG : NULL; // if last chunk, tag it.
        size_t adlen = (eof) ? 4 : 0;

        // Arguments order: 
        // ctx, cipher_text, mac, ad, ad_size, plain_text, text_size.
        // The mac comes after the encrypted chunk, thus:
        // - the mac is located at buf_out + len, and
        // - the total length to save is len + MAC_SIZE.
        crypto_aead_write(&ctx, buf_out, buf_out+len, ad, adlen, buf_in, len);

        // Write the cipher_text followed by the MAC to out.
        if ((write_bytes(out, buf_out, len + MAC_SIZE)) != len + MAC_SIZE) {
            err = ERR_WRITE;
            break;
        }
    } while(!eof);

    crypto_wipe(&ctx, sizeof(ctx)); // securely wipe the context.
    crypto_wipe(buf_in, CHUNKLEN); // securely wipe the buf_in.
    return err;
}

// Decrypt the 'in' file, using the key 'key' and the nonce 'nonce'
// and write decrypted chunks to the 'out' file.
static enum error decrypt(FILE *in, FILE *out, const uint8_t key[KEY_SIZE],
                          const uint8_t nonce[NONCE_SIZE])
{
    int eof = 0;
    enum error err = ERR_OK;

    uint8_t buf_out[CHUNKLEN];
    uint8_t buf_in[CHUNKLEN + MAC_SIZE];

    crypto_aead_ctx ctx;
    crypto_aead_init_x(&ctx, key, nonce);

    do {
        size_t len = read_bytes(in, buf_in, CHUNKLEN + MAC_SIZE);

        if (!len && ferror(in)) {
            err = ERR_READ;
            break;
        }

        eof = feof(in);
        uint8_t *ad = (eof) ? END_TAG : 0; // last chunk should've been tagged.
        size_t adlen = (eof) ? 4 : 0;

        // Arguments order: 
        // ctx, plain_text, mac, ad, ad_size, cipher_text, text_size.
        // The read 'len' bytes from 'in' already includes the mac, thus:
        // - the mac is located at buf_in + len - MAC_SIZE, and
        // - text_size == len - MAC_SIZE.
        if (crypto_aead_read(&ctx, buf_out, buf_in + len - MAC_SIZE, ad, adlen,
                             buf_in, len - MAC_SIZE)) {
            err = ERR_INVALID;
            break;
        }

        // Write the clear_text, without the MAC, to out.
        if ((write_bytes(out, buf_out, len - MAC_SIZE)) != len - MAC_SIZE) {
            err = ERR_WRITE;
            break;
        }
    } while(!eof);

    crypto_wipe(&ctx, sizeof(ctx)); // securely wipe the context.
    crypto_wipe(buf_out, CHUNKLEN); // securely wipe the buf_out.
    return err;
}

// Generate a KEY_SIZE bytes key from a passphrase and a salt (random)
// using Argon2i. This needs a work area that has to be allocated.
// If this allocation fails, securely wipe the passphrase and exit.
static enum error gen_key(uint8_t *passphrase, size_t passphrase_size,
                          uint8_t *salt, uint8_t key[KEY_SIZE])
{
    enum error err = ERR_OK;
    void *work_area = malloc(ARGON_NB_BLOCKS * 1024);

    if (work_area == NULL) {
        // Failed at allocating a work area, wipe passphrase and exit
        BAIL(ERR_NO_KEY);
    }

    crypto_argon2_config cfg = {
        .algorithm = CRYPTO_ARGON2_I,
        .nb_blocks = ARGON_NB_BLOCKS,
        .nb_passes = ARGON_NB_ITERATIONS,
        .nb_lanes  = ARGON_NB_LANES
    };

    crypto_argon2_inputs inputs = {
        .pass = passphrase,
        .salt = salt, 
        .pass_size = passphrase_size,
        .salt_size = ARGON_SALT_SIZE 
    };

    crypto_argon2_extras extras = {
        .key = NULL,
        .ad = NULL,
        .key_size = 0,
        .ad_size = 0
    };

    crypto_argon2(key, KEY_SIZE, work_area, cfg, inputs, extras);

    free(work_area);
    crypto_wipe(&cfg, sizeof(crypto_argon2_config));
    crypto_wipe(&inputs, sizeof(crypto_argon2_inputs));
    crypto_wipe(&extras, sizeof(crypto_argon2_extras));
bail:
    crypto_wipe(passphrase, passphrase_size);
    return err;
}

// Prompt the user to type in a passphrase (twice if needed), with a maximum
// size (capacity) of 'size'. Put the passphrase in 'passphrase' and its length
// in 'len'. Return an error code to tell what happened.
// This function behaves differently depending on the operation 'mode' in which
// it is called. See the passphrase_config structure defined earlier.
static enum error get_passphrase(uint8_t *passphrase, size_t size, int *len,
                               enum operation mode)
{
    enum error err = ERR_OK;
    struct passphrase_config config = passphrase_configs[mode];

    int r0 = read_password(passphrase, size, config.prompt);
    if (r0 == 0) {
        BAIL(ERR_PASS_READ_FAIL);
    }
    if (r0 < 0) {
        BAIL(ERR_PASS_TOO_BIG);
    }
    if (config.confirm) {
        // If no protection is needed, do not ask for a confirmation.
        if ((mode == MODE_KEYEDIT) && (!passphrase[0])) {
            BAIL(ERR_OK);
        }
        uint8_t tmp[MAXPASS];
        int r1 = read_password(tmp, sizeof(tmp), config.prompt_repeat);
        if (r1 == 0) {
            BAIL(ERR_PASS_READ_FAIL);
        }
        if (r0 != r1 || memcmp(passphrase, tmp, r0)) {
            BAIL(ERR_PASS_NOT_MATCH);
        }
        crypto_wipe(tmp, sizeof(tmp));
    }
bail:
    *len = r0;
    return err;
}

// Read keyfile to extract the key. Decrypt it if needed.
// To check if the key is protected, we check the last bit of the version:
// if it is set to '1', then the key is protected, otherwise it is not.
// A key if not protected consists of the last KEY_SIZE of the content
// of the file 'kf'.
// When protected using a passphrase, it should be decrypted using a key
// that will be generated using the given passphrase, the nonce (first
// NONCE_SIZE bytes of the file), and authenticated using the mac (next
// MAC_SIZE bytes following the nonce).
static enum error read_keyfile(FILE *kf, uint8_t key[KEY_SIZE])
{
    enum error err = ERR_OK;
    uint8_t content[KEYFILE_SIZE];
    uint8_t passphrase[MAXPASS];
    uint8_t prot_key[KEY_SIZE];
    int pwlen = 0;

    size_t len = read_bytes(kf, content, KEYFILE_SIZE);
    if ((len != KEYFILE_SIZE) || ferror(kf)) {
        BAIL(ERR_READ);
    }

    // Some pointers according to this keyfile format:
    // +----------------+------------+----------------------+-------------+
    // |    24 bytes    |  16 bytes  |       1 byte         |   32 bytes  |
    // +----------------+------------+----------------------+-------------+
    // |  RANDOM NONCE  |     MAC    | PROTECTION | VERSION |     KEY     |
    // +----------------+------------+----------------------+-------------+
    uint8_t *nonce = content;
    uint8_t *mac = content + NONCE_SIZE;
    uint8_t *version = mac + MAC_SIZE;
    uint8_t *fkey = version + 1;

    // Inspect the protection-version byte, and get its MSB.
    int protected = *version >> 7;
    if (!protected) {
        // Key is not protected. Copy the last KEY_SIZE bytes. 
        memcpy(key, fkey, KEY_SIZE);
        BAIL(ERR_OK);
    } else {
        // Ask the user to provide a passphrase to decrypt the key.
        err = get_passphrase(passphrase, MAXPASS, &pwlen, MODE_DECRYPT);
        if (err != ERR_OK) {
            BAIL(err);
        }
        // Generate the protection key using this passphrase and the nonce.
        err = gen_key(passphrase, pwlen, nonce, prot_key);
        if (err != ERR_OK) {
            BAIL(err);
        }
        // Decrypt the key in the file (i.e., 'fkey') into 'key'.
        // If it fails, bail out.
        if (crypto_aead_unlock(key, mac, prot_key, nonce, NULL, 0, fkey,
                               KEY_SIZE) < 0) {
            BAIL(ERR_INVALID);
        }
    }
bail: // Clear sensitive data, and return err.
    crypto_wipe(prot_key, sizeof(prot_key));
    crypto_wipe(passphrase, sizeof(passphrase));
    return err;
}

// Write the key 'key' to the file 'kf'.
// Fill a KEYFILE_SIZE buffer ('content') with random data.
// Ask the user for a passphrase:
// 1) if the given passphrase is empty, then the key should not be protected.
// We set the 'protection bit' to '0', and we proceed to copy it as is to the
// last KEY_SIZE bytes of 'content'.
// 2) if the passphrase is not empty, then:
// 2-a) We set the 'protection bit' to '1'.
// 2-b) We generate an encryption key (prot_key) using the given passphrase and
// the 'nonce' (first NONCE_SIZE bytes of 'content'), and encrypt the provided
// key 'key' and put the encrypted key in the last KEY_SIZE bytes of 'content'.
// 3) We write the 'content' to 'kf'.
static enum error write_keyfile(FILE *kf, uint8_t key[KEY_SIZE])
{
    enum error err = ERR_OK;
    uint8_t content[KEYFILE_SIZE];
    uint8_t passphrase[MAXPASS]; // Key protection passphrase.
    uint8_t prot_key[KEY_SIZE];
    int pwlen = 0; // Length of protection passphrase.

    // Some pointers according to this keyfile format:
    // +----------------+------------+----------------------+-------------+
    // |    24 bytes    |  16 bytes  |       1 byte         |   32 bytes  |
    // +----------------+------------+----------------------+-------------+
    // |  RANDOM NONCE  |     MAC    | PROTECTION | VERSION |     KEY     |
    // +----------------+------------+----------------------+-------------+
    uint8_t *nonce = content;
    uint8_t *mac = content + NONCE_SIZE;
    uint8_t *version = mac + MAC_SIZE;
    uint8_t *fkey = version + 1;

    // fill the content with random bytes.
    if (fillrand(content, KEYFILE_SIZE)) { // returns 0 on success
        BAIL(ERR_NO_RANDOM);
    }
    // Passphrase-protect the generated key? Check the value of passphrase[0].
    err = get_passphrase(passphrase, MAXPASS, &pwlen, MODE_KEYEDIT);
    if (err != ERR_OK) {
        BAIL(err);
    }
    if (!passphrase[0]) { // No protection asked.
        *version = 0 | KEYFILE_VERSION;
        memcpy(fkey, key, KEY_SIZE);
        err = ERR_OK;
    } else { // Protect the key with a passphrase and the random nonce.
        *version = 0x80 | KEYFILE_VERSION;
        // Generate an encryption key (for the given key) using the passphrase
        // and the nonce (located at the beginning of 'content').
        err = gen_key(passphrase, pwlen, nonce, prot_key);
        if (err != ERR_OK) {
            BAIL(err);
        }
        // Encrypt the given key using the generated key.
        crypto_aead_lock(fkey, mac, prot_key, nonce, NULL, 0, key, KEY_SIZE);
    }
    // Write the key (content) into kf.
    if (write_bytes(kf, content, KEYFILE_SIZE) != KEYFILE_SIZE) {
        BAIL(ERR_WRITE);
    }
bail:
    crypto_wipe(passphrase, sizeof(passphrase));
    crypto_wipe(prot_key, sizeof(prot_key));
    return err;
}

// Print the usage message.
static void print_usage(void)
{
    const char **s = usage;
    while (*s) {
        fputs(*s++, stdout);
        fputc('\n', stdout);
    }
}

// Print the version information.
static void print_version(void)
{
    fputs(PROG " " PROG_VERSION "\n", stdout);
}

int main(int argc, char *argv[])
{
    enum operation mode = MODE_NONE;

    struct optparse_long longopts[] = {
        {"generate", 'g', OPTPARSE_NONE},
        {"encrypt", 'e', OPTPARSE_NONE},
        {"decrypt", 'd', OPTPARSE_NONE},
        {"keyfile", 'k', OPTPARSE_REQUIRED},
        {"passphrase", 'p', OPTPARSE_OPTIONAL},
        {"uid", 'u', OPTPARSE_REQUIRED},
        {"keyedit", 'm', OPTPARSE_REQUIRED},
        {"help", 'h', OPTPARSE_NONE},
        {"version", 'V', OPTPARSE_NONE},
        {0}
    };

    uint8_t header[HEADER_SIZE];
    uint8_t key[KEY_SIZE];
    uint8_t passphrase[MAXPASS];
    uint8_t use_passphrase = 0; // do we use keyfiles, or passphrases?
    uint8_t uid[MAXUID]; // User ID for deterministic key generation.
    uint8_t uid_hash[ARGON_SALT_SIZE]; // User ID hash to be used as a salt.
    int pwlen = 0; // passphrase length
    int uilen = 0; //uid length

    char *keyfile = NULL;
    char *infile = NULL;
    char *outfile = NULL;
    FILE *kf = NULL;
    FILE *in = NULL;
    FILE *out = NULL;

    enum error err = ERR_OK;
    int exitcode = 0;

    int option;
    struct optparse options;

    (void)argc;
    optparse_init(&options, argv);
    while ((option = optparse_long(&options, longopts, NULL)) != -1) {
        switch (option) {
            case 'g':
                mode = MODE_KEYGEN;
                break;
            case 'e':
                mode = MODE_ENCRYPT;
                break;
            case 'd':
                mode = MODE_DECRYPT;
                break;
            case 'k':
                keyfile = options.optarg;
                break;
            case 'm':
                mode = MODE_KEYEDIT;
                keyfile = options.optarg;
                break;
            case 'p':
                use_passphrase = 1;
                if (options.optarg) {
                    pwlen = strlen(options.optarg) + 1;
                    if (pwlen > MAXPASS) {
                        BAIL(ERR_PASS_TOO_BIG);
                    }
                    memcpy(passphrase, options.optarg, pwlen);
                }
                break;
            case 'u':
                use_passphrase = 1;
                if (options.optarg) {
                    uilen = strlen(options.optarg) + 1;
                    if (uilen > MAXUID) {
                        BAIL(ERR_UID_TOO_BIG);
                    }
                    memcpy(uid, options.optarg, uilen);
                }
                break;
            case 'V':
                print_version();
                BAIL(ERR_OK);
            case '?':
            case 'h':
            default:
                print_usage();
                BAIL(ERR_OK);
        }
    }

    // What are we using?  A keyfile or a passphrase?
    if (keyfile) { // Keyfile-based operations.
        kf = fopen(keyfile, "rb");
        if (!kf || (read_keyfile(kf, key) != ERR_OK)) {
            BAIL(ERR_KEYFILE);
        }
    } else if (use_passphrase && !pwlen) {
        // Ask the user to type a passphrase.
        err = get_passphrase(passphrase, MAXPASS, &pwlen, mode);
        if (err != ERR_OK) {
            BAIL(err);
        }
    } else if (!pwlen && (mode != MODE_KEYGEN)) {
        print_usage();
        BAIL(ERR_OK);
    }

    // Set the standard input and output to binary mode (_WIN32)
    binary_stdio();

    // Open the input file.
    // infile is not needed for MODE_KEYGEN.
    if (mode != MODE_KEYGEN && mode != MODE_KEYEDIT) {
        infile =  optparse_arg(&options);
        in = !infile || !strcmp(infile, "-") ? stdin : fopen(infile, "rb");
        if (!in && (mode != MODE_KEYGEN)) {
            BAIL(ERR_INPUT_FILE);
        }
    }

    // Open the output file.
    if (mode != MODE_KEYEDIT) {
        outfile =  optparse_arg(&options);
        out = !outfile ? stdout : fopen(outfile, "wb");
        if (!out) {
            BAIL(ERR_OUTPUT_FILE);
        }
    }

    switch(mode) {
        case MODE_KEYGEN:
            // Prepare a key with KEY_SIZE random bytes.
            if (fillrand(key, KEY_SIZE)) {
                BAIL(ERR_NO_RANDOM);
            }
            // If the key to be generated depends on a uid and a passphrase,
            // generate a deterministic one with the same value when given 
            // the same uid and passphrase.
            if (use_passphrase) {
                // Hash the uid to use it as a salt for key derivation.
                crypto_blake2b(uid_hash, ARGON_SALT_SIZE, uid, uilen);
                // Generate a key using the passphrase and this salt.
                err = gen_key(passphrase, pwlen, uid_hash, key);
                if (err != ERR_OK) {
                    BAIL(err);
                }
            }
            // Write the random (or uid-based key) to the 'out' file.
            err = write_keyfile(out, key);
            if (err !=  ERR_OK) {
                BAIL(err);
            }
            break;
        case MODE_KEYEDIT:
            // Edit a key's passphrase.
            // If the key has a passphrase, by editing it, we can change or
            // remove the passphrase. If does not, we can add a protection
            // passphrase.
            fclose(kf); // close the keyfile, and reopen it in write mode.
            if (!(kf = fopen(keyfile, "wb"))) {
               BAIL(ERR_KEYFILE);
            }
            err = write_keyfile(kf, key);
            if (err !=  ERR_OK) {
                BAIL(err);
            }
            break;
        case MODE_ENCRYPT:
            // Start with the header totally clear (set to 0).
            crypto_wipe(header, HEADER_SIZE);
            // Put the version in the 25th byte of the header.
            header[NONCE_SIZE] = FILE_VERSION;
            // Fill the first NONCE_SIZE bytes of the header with random bytes.
            if (fillrand(header, NONCE_SIZE)) { // returns 0 on success
                BAIL(ERR_NO_RANDOM);
            }
            // If passphrase-based encryption, generate a key from the
            // passphrase and the first ARGON_SALT_SIZE bytes in the header.
            if (use_passphrase) {
                err = gen_key(passphrase, pwlen, header, key);
                if (err != ERR_OK) {
                    BAIL(err);
                }
            }
            // Write the encrypted file's header.
            if (write_bytes(out, header, HEADER_SIZE) != HEADER_SIZE) {
                BAIL(ERR_WRITE);
            }
            // Encrypt 'in' into 'out'.
            err = encrypt(in, out, key, header);
            if (err != ERR_OK) {
                BAIL(err);
            }
            break;
        case MODE_DECRYPT:
            // Read the encrypted file's header.
            if (read_bytes(in, header, HEADER_SIZE) != HEADER_SIZE) {
                BAIL(ERR_READ);
            }
            // Does the version match?
            if (header[NONCE_SIZE] != FILE_VERSION) {
                BAIL(ERR_VERSION_MISMATCH);
            }
            // If passphrase-based decryption, generate a key from the
            // passphrase and the first ARGON_SALT_SIZE bytes in the header.
            if (use_passphrase) {
                err = gen_key(passphrase, pwlen, header, key);
                if (err != ERR_OK) {
                    BAIL(err);
                }
            }
            // Decrypt 'in' into 'out'.
            err = decrypt(in, out, key, header);
            if (err != ERR_OK) {
                BAIL(err);
            }
            break;
        case MODE_NONE:
            print_usage();
            BAIL(ERR_OK);
    }

// Clean everything and exit.
bail: 
    // Safely wipe sensitive info.
    crypto_wipe(key, KEY_SIZE);
    crypto_wipe(passphrase, MAXPASS);
    crypto_wipe(uid, MAXUID);
    crypto_wipe(uid_hash, ARGON_SALT_SIZE);

    // Close files if opened.
    if (kf) fclose(kf);
    if (in) fclose(in);
    if (out) fclose(out);

    // Display error message if any.
    if (err != ERR_OK) {
        fprintf(stderr, "%s: %s\n", PROG, errmsg[err]);
        exitcode = 1;
    }

    return exitcode;
}
