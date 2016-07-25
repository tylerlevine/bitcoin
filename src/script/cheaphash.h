// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_SCRIPT_CHEAPHASH_H
#define BITCOIN_SCRIPT_CHEAPHASH_H
#include <boost/unordered_set.hpp>
/**
 * We're hashing a nonce into the entries themselves, so we don't need extra
 * blinding in the set hash computation.
 */
class CSignatureCacheHasher
{
public:
    size_t operator()(const uint256& key) const {
        return key.GetCheapHash();
    }
};

using cache_map_type =  boost::unordered_set<uint256, CSignatureCacheHasher>;
#endif// BITCOIN_SCRIPT_CHEAPHASH_H
