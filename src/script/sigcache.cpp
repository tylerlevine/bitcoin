// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "sigcache.h"

#include "memusage.h"
#include "pubkey.h"
#include "random.h"
#include "uint256.h"
#include "util.h"

#include "cuckoocache.h"

namespace {

/**
 * We're hashing a nonce into the entries themselves, so we don't need extra
 * blinding in the set hash computation.
 */
class SignatureCacheHasher
{
public:
    uint32_t operator()(const uint256& key, uint8_t n) const
    {
        uint32_t u {0};
        std::memcpy(&u, key.begin()+(sizeof(uint8_t)*3*n), 3);
        return u;
    }
};

/**
 * Valid signature cache, to avoid doing expensive ECDSA signature checking
 * twice for every transaction (once when accepted into memory pool, and
 * again when accepted into the block chain)
 */
class SignatureCache
{
private:
     //! Entries are SHA256(nonce || signature hash || public key || signature):
    uint256 nonce;
    typedef CuckooCache<uint256, SignatureCacheHasher> map_type;
    map_type setValid;

public:
    SignatureCache()
    {
        GetRandBytes(nonce.begin(), 32);
    }

    void
    ComputeEntry(uint256& entry, const uint256 &hash, const std::vector<unsigned char>& vchSig, const CPubKey& pubkey)
    {
        CSHA256().Write(nonce.begin(), 32).Write(hash.begin(), 32).Write(&pubkey[0], pubkey.size()).Write(&vchSig[0], vchSig.size()).Finalize(entry.begin());
    }

    bool
    Get(const uint256& entry)
    {
        return setValid.contains(entry);
    }

    bool
    GetErase(const uint256& entry)
    {
        auto it = setValid.find(entry);
        if (it != setValid.end()) {
            setValid.garbage_collect(it);
            return true;
        }
        return false;
    }

    void Set(uint256& entry)
    {
        size_t nMaxCacheSize = GetArg("-maxsigcachesize", DEFAULT_MAX_SIG_CACHE_SIZE) * ((size_t) 1 << 20);
        if (nMaxCacheSize <= 0) return;
        setValid.resize_bytes(nMaxCacheSize);
        setValid.insert(entry);
    }
};

static SignatureCache signatureCache;
}


bool CachingTransactionSignatureChecker::VerifySignature(const std::vector<unsigned char>& vchSig, const CPubKey& pubkey, const uint256& sighash) const
{
    uint256 entry;
    signatureCache.ComputeEntry(entry, sighash, vchSig, pubkey);
    if (!store) {
        if (signatureCache.GetErase(entry))
            return true;

        if (!TransactionSignatureChecker::VerifySignature(vchSig, pubkey, sighash))
            return false;

        return true;
    } else {
        std::lock_guard<std::mutex> l(mtx);
        if(signatureCache.Get(entry)) {
            return true;
        }

        if (!TransactionSignatureChecker::VerifySignature(vchSig, pubkey, sighash))
            return false;

        if (store) {
            signatureCache.Set(entry);
        }
        return true;
    }
}
std::mutex CachingTransactionSignatureChecker::mtx {};
