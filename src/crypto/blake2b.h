// Copyright (c) 2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CRYPTO_BLAKE2B_H
#define BITCOIN_CRYPTO_BLAKE2B_H

#include <stdint.h>
#include <stdlib.h>
#include "crypto/blake2/blake2b.h"

/** A hasher class for SHA-256. */
class Blake2B
{
private:
    blake2b_state S;

public:
    static const size_t OUTPUT_SIZE = 32;

    Blake2B() {
        blake2b_init(&S, 32);
    };
    Blake2B& Write(const unsigned char* data, size_t len) {
        blake2b_update(&S, data, len);
        return *this;
    }
    void Finalize(unsigned char hash[OUTPUT_SIZE]) {
        blake2b_final(&S, hash, OUTPUT_SIZE);
    }

    Blake2B& Reset() {
        blake2b_init(&S, 32);
        return *this;
    }
};

#endif // BITCOIN_CRYPTO_SHA256_H
