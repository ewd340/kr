#! /bin/sh

set -e

IGNORE="passgen|monocypher|optparse|util"
COVDIR="cov"

make clean
make test CC="clang -std=c99" CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping"
llvm-profdata merge default.profraw -o all.profdata
llvm-cov show  -ignore-filename-regex=$IGNORE -instr-profile=all.profdata "./test.out"
llvm-cov report -ignore-filename-regex=$IGNORE -instr-profile=all.profdata "./test.out"
llvm-cov show -ignore-filename-regex=$IGNORE -format html -instr-profile=all.profdata "./test.out" --output-dir=$COVDIR
