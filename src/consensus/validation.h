// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_VALIDATION_H
#define BITCOIN_CONSENSUS_VALIDATION_H

#include <string>
#include "version.h"
#include "consensus/consensus.h"
#include "primitives/transaction.h"
#include "primitives/block.h"

/** "reject" message codes */
static const unsigned char REJECT_MALFORMED = 0x01;
static const unsigned char REJECT_INVALID = 0x10;
static const unsigned char REJECT_OBSOLETE = 0x11;
static const unsigned char REJECT_DUPLICATE = 0x12;
static const unsigned char REJECT_NONSTANDARD = 0x40;
// static const unsigned char REJECT_DUST = 0x41; // part of BIP 61
static const unsigned char REJECT_INSUFFICIENTFEE = 0x42;
static const unsigned char REJECT_CHECKPOINT = 0x43;

/** Reject codes greater or equal to this can be returned by AcceptToMemPool
 * for transactions, to signal internal conditions. They cannot and should not
 * be sent over the P2P network.
 *
 * These error codes are not consensus, but consensus changes should avoid using them
 * unnecessarily so as not to cause needless churn in core-based clients.
 */
static const unsigned int REJECT_INTERNAL = 0x100;
/** Too high fee. Can not be triggered by P2P transactions */
static const unsigned int REJECT_HIGHFEE = 0x100;

/** Capture information about block/transaction validation */
class CValidationState {
private:
    enum mode_state {
        MODE_VALID,   //!< everything ok
        MODE_INVALID, //!< network rule violation (DoS value may be set)
        MODE_ERROR,   //!< run-time error
    } mode;
    int nDoS;
    std::string strRejectReason;
    unsigned int chRejectCode;
    bool corruptionPossible;
    std::string strDebugMessage;
    bool DoS(int level, bool ret = false,
             unsigned int chRejectCodeIn=0, const std::string &strRejectReasonIn="",
             bool corruptionIn=false,
             const std::string &strDebugMessageIn="") {
        chRejectCode = chRejectCodeIn;
        strRejectReason = strRejectReasonIn;
        corruptionPossible = corruptionIn;
        strDebugMessage = strDebugMessageIn;
        if (mode == MODE_ERROR)
            return ret;
        nDoS += level;
        mode = MODE_INVALID;
        return ret;
    }
    bool Invalid(bool ret = false,
                 unsigned int _chRejectCode=0, const std::string &_strRejectReason="",
                 const std::string &_strDebugMessage="") {
        return DoS(0, ret, _chRejectCode, _strRejectReason, false, _strDebugMessage);
    }
public:
    CValidationState() : mode(MODE_VALID), nDoS(0), chRejectCode(0), corruptionPossible(false) {}
    bool BadBlockHeader(const std::string &_strRejectReason="",
                 const std::string &_strDebugMessage="", int level=100, unsigned int _chRejectCode=REJECT_INVALID) {
        return DoS(level, false, _chRejectCode, _strRejectReason, false, _strDebugMessage);
    }
    bool CorruptBlockHeader(const std::string &_strRejectReason="",
                 const std::string &_strDebugMessage="", int level=100) {
        return DoS(level, false, REJECT_INVALID, _strRejectReason, true, _strDebugMessage);
    }
    bool ForkingBlockHeaderDisallowed() {
        return DoS(100, false, REJECT_CHECKPOINT, "bad-fork-prior-to-checkpoint");
    }
    bool BadBlock(const std::string &_strRejectReason="",
                 const std::string &_strDebugMessage="", int level=100) {
        return DoS(level, false, REJECT_INVALID, _strRejectReason, false, _strDebugMessage);
    }
    bool CorruptBlock(const std::string &_strRejectReason="",
                 const std::string &_strDebugMessage="", int level=100) {
        return DoS(level, false, REJECT_INVALID, _strRejectReason, true, _strDebugMessage);
    }
    bool BadTx(const std::string &_strRejectReason="",
                 const std::string &_strDebugMessage="", int level=100, unsigned int _chRejectCode=REJECT_INVALID) {
        return DoS(level, false, _chRejectCode, _strRejectReason, false, _strDebugMessage);
    }
    bool CorruptTx(const std::string &_strRejectReason="",
                 const std::string &_strDebugMessage="", int level=100) {
        return DoS(level, false, REJECT_INVALID, _strRejectReason, true, _strDebugMessage);
    }
    bool NonStandardTx(const std::string &_strRejectReason="",
                 const std::string &_strDebugMessage="", bool corrupted=false, int level=0) {
        return DoS(level, false, REJECT_NONSTANDARD, _strRejectReason, corrupted, _strDebugMessage);
    }

    bool DuplicateData(const std::string &_strRejectReason="",
                 const std::string &_strDebugMessage="") {
        return DoS(0, false, REJECT_DUPLICATE, _strRejectReason, false, _strDebugMessage);
    }
    bool RejectFee(unsigned int _chRejectCode, const std::string &_strRejectReason="",
                 const std::string &_strDebugMessage="") {
        assert(_chRejectCode == REJECT_INSUFFICIENTFEE || _chRejectCode == REJECT_HIGHFEE);
        return DoS(0, false, _chRejectCode, _strRejectReason, false, _strDebugMessage);
    }
    bool Error(const std::string& strRejectReasonIn) {
        if (mode == MODE_VALID)
            strRejectReason = strRejectReasonIn;
        mode = MODE_ERROR;
        return false;
    }
    bool IsValid() const {
        return mode == MODE_VALID;
    }
    bool IsInvalid() const {
        return mode == MODE_INVALID;
    }
    bool IsError() const {
        return mode == MODE_ERROR;
    }
    bool IsInvalid(int &nDoSOut) const {
        if (IsInvalid()) {
            nDoSOut = nDoS;
            return true;
        }
        return false;
    }
    bool CorruptionPossible() const {
        return corruptionPossible;
    }
    void SetCorruptionPossible() {
        corruptionPossible = true;
    }
    unsigned int GetRejectCode() const { return chRejectCode; }
    std::string GetRejectReason() const { return strRejectReason; }
    std::string GetDebugMessage() const { return strDebugMessage; }
    void SetDebugMessage(const std::string& msg){ strDebugMessage = msg; }
};

// These implement the weight = (stripped_size * 4) + witness_size formula,
// using only serialization with and without witness data. As witness_size
// is equal to total_size - stripped_size, this formula is identical to:
// weight = (stripped_size * 3) + total_size.
static inline int64_t GetTransactionWeight(const CTransaction& tx)
{
    return ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS) * (WITNESS_SCALE_FACTOR - 1) + ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION);
}
static inline int64_t GetBlockWeight(const CBlock& block)
{
    return ::GetSerializeSize(block, SER_NETWORK, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS) * (WITNESS_SCALE_FACTOR - 1) + ::GetSerializeSize(block, SER_NETWORK, PROTOCOL_VERSION);
}

#endif // BITCOIN_CONSENSUS_VALIDATION_H
