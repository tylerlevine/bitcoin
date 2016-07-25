// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SCRIPT_SIGCACHE_H
#define BITCOIN_SCRIPT_SIGCACHE_H

#include "script/interpreter.h"
#include "script/cheaphash.h"

#include <vector>
#include <boost/thread.hpp>
#include <boost/unordered_set.hpp>

// DoS prevention: limit cache size to less than 40MB (over 500000
// entries on 64-bit systems).
static const unsigned int DEFAULT_MAX_SIG_CACHE_SIZE = 40;

class CPubKey;


/**
 * Valid signature cache, to avoid doing expensive ECDSA signature checking
 * twice for every transaction (once when accepted into memory pool, and
 * again when accepted into the block chain)
 */
class CSignatureCache
{
public:
    using map_type = cache_map_type;
private:
     //! Entries are SHA256(nonce || signature hash || public key || signature):
    uint256 nonce;
    map_type setValid;
    boost::shared_mutex cs_sigcache;
    size_t nMaxCacheSize;
public:
    CSignatureCache();
    void adjustsize(size_t cache_size);
    void
    ComputeEntry(uint256& entry, const uint256 &hash, const std::vector<unsigned char>& vchSig, const CPubKey& pubkey);

    bool Get(const uint256& entry);

    void Erase(const uint256& entry);

    bool GetReadOnly(const uint256& entry, std::function<void()>& cleanup);
    void QuickErase(map_type::const_iterator found);

    void Set(const uint256& entry);
};

class CachingTransactionSignatureChecker : public TransactionSignatureChecker
{
private:
    bool store;
    bool readOnly;
    std::function<void()>& cleanup;
public:
    CachingTransactionSignatureChecker(const CTransaction* txToIn, unsigned int nInIn, const CAmount& amount, bool storeIn, bool readOnlyIn, 
    std::function<void()>& cleanup_) : TransactionSignatureChecker(txToIn, nInIn, amount), store(storeIn), readOnly(readOnlyIn), cleanup(cleanup_) {}

    bool VerifySignature(const std::vector<unsigned char>& vchSig, const CPubKey& vchPubKey, const uint256& sighash) const;
};

#endif // BITCOIN_SCRIPT_SIGCACHE_H
