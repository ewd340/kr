# kr : __a simple file encryption/decryption tool.__

`kr` is a simple file encryption/decryption program based on
[Monocypher](https://monocypher.org/). Under the hood, it uses the incremental
AEAD interface of Monocypher to encrypt/decrypt files using
[XChaCha20-Poly1305](https://monocypher.org/manual/aead).

`kr` offers two modes of operation:

- Keyfile-based: a private key is stored on the user's machine and is used to
  encrypt and decrypt files. 

- Passphrase-based: an encryption/decryption key is generated, on the fly, using
  Argon2i (with a random salt).

When using keyfiles, `kr` can help you generate either random or deterministic
keyfiles (based on a passphrase and a uid). See Keyfiles Management below.

## Installation

Clone this repository, then run:

```
$ make install
```

By default, this will install the `kr` program to `/usr/local/bin`, and the
manual page in `/usr/local/share/man/man1` You can change that by adding
`PREFIX=~/.local` (for example) to the previous command.

## Usage:

Invoking `kr` with the `-h` (or `--help`) option will give you a summary of its
usage. Read on for more details.


As stated above, `kr` may be used either with passphrases or keyfiles. Before we
dive into the encryption/decryption operations, let us explore keyfiles
management first.

### Keyfiles Management

`kr` is based on symmetric private keys. These keys may be totally _random_ or
deterministic (predictable). Both types of keys serve to encrypt and decrypt,
and may be protected with a passphrase if the user wants to.

#### Random Keyfiles Generation `-g`

To generate a random key, one can simply invoke `kr` as follows:

```
$ kr -g ~/key.sec
```
The user is, then,  prompted to type a passphrase if they want to protect the
generated key.

#### Predictable Keyfiles Generation `-g -u`

Instead of storing private keys on disk and carrying them from a machine to
another, one can opt to generate them on the spot every time they need them.
Indeed, given a passphrase and a unique user ID (a simple string such as a
username, an email address, etc.), `kr` will generate the _same_ key for the
_same_ pair (passphrase, userID) on every invocation. For example:

```
$ kr -guUSERID -p"PASS PHRASE" ~/key.sec
```
 Or 

```
$ kr -g --uid=USERID --passphrase="PASS PHRASE" ~/key.sec
```

`kr` will use the uid `USERID`and the passphrase `"PASS PHRASE"` to generate a
key that will be stored in `~/key.sec`. Note that if the passphrase is not
specified in the command above, `kr` will prompt the user to type it (and
confirm it). Long options are also available as follows:

```
$ kr --generate --uid=USERID --passphrase="PASS PHRASE" ~/key.sec
```

Note that if the output keyfile is not provided in the two commands above, the
key will be output to `stdout`.

#### Editing Keyfiles `-c`

One can add, edit, or remove the protection passphrase of a given keyfile simply
by using the `--edit` (or `-c`) option as follows:

```
$ kr -c ~/key.sec
```

### Encryption/Decryption

#### Keyfile-based Encryption/Decryption

##### Encryption `-e -k`

```
$ kr -e -k ~/.key.sec inputfile outputfile
```
Encrypts the input file `inputfile` using the key stored in `~/.key.sec` and
puts the output in `outputfile` (or `stdout` if no output file is provided in
the command above).

We can also use the long options:

```
$ kr --encrypt --keyfile ~/.key.sec inputfile outputfile
```

##### Decryption `-d -k`

```
$ kr -d -k ~/.key.sec inputfile outputfile
```
Decrypts the encrypted  input file `inputfile` using the key stored in
`~/.key.sec` and puts the output in `outputfile.` (or `stdout` if no output file
is provided in the command above)

Or using the long options:

```
$ kr --decrypt --keyfile ~/.key.sec inputfile outputfile
```

#### Passphrase-based Encryption/Decryption

Instead of using key files, we can use passphrases as follows:

##### Encryption `-e -p`

```
$ kr -e -p"PASS PHRASE" inputfile outputfile
```
Encrypts the input file `inputfile` using the passphrase `"PASS PHRASE"` and
puts the output in `outputfile` (or `stdout` if no output file is provided in
the command above). Note that you are prompted to type a passphrase (and confirm
it) if the passphrase is not provided in the command line above.

We can also use the long options:

```
$ kr --encrypt --passphrase="PASS PHRASE" inputfile outputfile
```

##### Decryption `-d -p`

```
$ kr -d -p"PASS PHRASE" inputfile outputfile
```
Decrypts the encrypted input file `inputfile` using the passphrase `"PASS
PHRASE"` and puts the output in `outputfile`. (or `stdout` if no output file is
provided in the command above). Note that you are prompted to type a passphrase
if the passphrase is not provided in the command line above.

Or using the long options:

```
$ kr --decrypt --passphrase="PASS PHRASE" inputfile outputfile
```

### Support for streams

`kr` is able to process streams as well. For instance, these examples with
pipes:

```
$ echo 'Hello, world!' | kr -epPASS | kr -dpPASS
```
or with keyfiles 

```
$ echo 'Hello, world!' | kr -ek ~/.key.sec | kr -dk ~/.key.sec

```
will output, as you might have guessed it, the string `Hello, world!`.


**A note on passphrases**: It is not advisable to use passphrases in clear in
the command line. They will most probably be stored in your shell's history.
Thus, leaving the `-p` option empty and making the program prompt you to type
the passphrase is preferable.

## Disclaimer and thanks

I am *not* a cryptologist. This code is written for my own use. Use it at your
own risk. It is provided as is, and put in the public domain (please see the
UNLICENSE file). Your contributions, ideas, fixes, and suggestions are most
welcome.

A special *thank you!* goes to:

- @LoupVaillant and the contributors to the Monocypher project.
- @skeeto for his awesome C code of which I borrowed (and learned a lot).
  Namely, `kr` started as an imitation of his
  [monocrypt](https://github.com/skeeto/scratch/tree/master/monocrypt) project,
  and uses [Optparse](https://github.com/skeeto/optparse) and two other
  functions (_read_password_ and _fillrand_).
