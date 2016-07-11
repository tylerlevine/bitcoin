// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_CONSENSUS_H
#define BITCOIN_CONSENSUS_CONSENSUS_H

#include "amount.h"
#include "params.h"

#include <stdint.h>
#include <vector>

class CBlock;
class CBlockHeader;
class CBlockIndex;
class CCoinsViewCache;
class CTransaction;
class CUtxoView;
class CValidationState;

/** The maximum allowed size for a serialized block, in bytes (only for buffer size limits) */
static const unsigned int MAX_BLOCK_SERIALIZED_SIZE = 4000000;
/** The maximum allowed cost for a block, see BIP 141 (network rule) */
static const unsigned int MAX_BLOCK_COST = 4000000;
/** The maximum allowed size for a block excluding witness data, in bytes (network rule) */
static const unsigned int MAX_BLOCK_BASE_SIZE = 1000000;
/** The maximum allowed number of signature check operations in a block (network rule) */
static const int64_t MAX_BLOCK_SIGOPS_COST = 80000;
/** Coinbase transaction outputs can only be spent after this number of new blocks (network rule) */
static const int COINBASE_MATURITY = 100;

/**
 * Consensus validations (levels: Script, Header, Transaction and Block):
 * Check_ is for functions that check a level for some particular
 *  provided data or none (for most basic checks).
 * Verify_ means all data provided was enough for this level and its
 * "consensus-verified" in a particular chain.
 */
namespace Consensus {
} // namespace Consensus

/** Transaction validation functions */

/**
 * Context-independent CTransaction validity checks.
 * Nobody should spend an extra cycle on a transaction that doesn't pass this.
 */
bool CheckTransaction(const CTransaction& tx, CValidationState& state);

namespace Consensus {

/**
 * Check whether all inputs of this transaction are valid (no double spends and amounts)
 * This does not modify the UTXO set. This does not check scripts and sigs.
 * Preconditions: tx.IsCoinBase() is false.
 */
bool CheckTxInputs(const CTransaction& tx, CValidationState& state, const CCoinsViewCache& inputs, int nSpendHeight, CAmount& nFees);

/**
 * Checks specific to coinbase transactions.
 * Preconditions: tx.IsCoinBase() is true.
 */
bool CheckTxCoinbase(const CTransaction& tx, CValidationState& state, const int64_t flags, const int64_t nHeight);

/**
 * Check whether that all scripts (and signatures) of the inputs of this transaction are valid.
 * This does not modify the UTXO set.
 * Preconditions: tx.IsCoinBase() is false.
 */
bool CheckTxInputsScripts(const CTransaction& tx, CValidationState& state, const CCoinsViewCache& inputs, unsigned int flags, bool cacheStore);

/**
 * Fully verify a CTransaction.
 * @TODO this is incomplete, among other things, the scripts are not checked yet.
 */
bool VerifyTx(const CTransaction& tx, CValidationState& state, const int64_t flags, const int64_t nHeight, const int64_t nMedianTimePast, const int64_t nBlockTime, const CCoinsViewCache& inputs, const int64_t nSpendHeight, const CBlockIndex* pindexPrev, bool fScriptChecks, bool cacheStore, CAmount& nFees, int64_t& nSigOpsCost);

} // namespace Consensus

/** Header validation functions */

/**
 * Context-independent validity checks
 */
bool CheckBlockHeader(const CBlockHeader& block, CValidationState& state, const Consensus::Params& consensusParams, bool fCheckPOW = true);

/**
 * Context-dependent validity checks.
 *  By "context", we mean only the previous block headers, but not the UTXO
 *  set; UTXO-related validity checks are done in ConnectBlock().
 */
bool ContextualCheckBlockHeader(const CBlockHeader& block, CValidationState& state, const Consensus::Params& consensusParams, const CBlockIndex* pindexPrev, int64_t nAdjustedTime);

namespace Consensus {

/**
 * Fully verify a CBlockHeader.
 */
bool VerifyBlockHeader(const CBlockHeader& block, CValidationState& state, const Consensus::Params& consensusParams, int64_t nAdjustedTime, const CBlockIndex* pindexPrev, bool fCheckPOW);

} // namespace Consensus

/** Block validation functions */

/** Context-independent validity checks */
bool CheckBlock(const CBlock& block, CValidationState& state, const Consensus::Params& consensusParams, bool fCheckPOW = true, bool fCheckMerkleRoot = true);


/** Auxiliary functions for transaction validation (ideally should not be exposed) */

/**
 * Count ECDSA signature operations the old-fashioned (pre-0.6) way
 * @return number of sigops this transaction's outputs will produce when spent
 * @see CTransaction::FetchInputs
 */
unsigned int GetLegacySigOpCount(const CTransaction& tx);

/**
 * Count ECDSA signature operations in pay-to-script-hash inputs.
 * 
 * @param[in] mapInputs Map of previous transactions that have outputs we're spending
 * @return maximum number of sigops required to validate this transaction's inputs
 * @see CTransaction::FetchInputs
 */
unsigned int GetP2SHSigOpCount(const CTransaction& tx, const CCoinsViewCache& mapInputs);

/**
 * Compute total signature operation cost of a transaction.
 * @param[in] tx     Transaction for which we are computing the cost
 * @param[in] inputs Map of previous transactions that have outputs we're spending
 * @param[out] flags Script verification flags
 * @return Total signature operation cost of tx
 */
int64_t GetTransactionSigOpCost(const CTransaction& tx, const CCoinsViewCache& inputs, int flags);

/**
 * Check if transaction is final and can be included in a block with the
 * specified height and time. Consensus critical.
 */
bool IsFinalTx(const CTransaction &tx, int nBlockHeight, int64_t nBlockTime);

/**
 * Calculates the block height and previous block's median time past at
 * which the transaction will be considered final in the context of BIP 68.
 * Also removes from the vector of input heights any entries which did not
 * correspond to sequence locked inputs as they do not affect the calculation.
 */
std::pair<int, int64_t> CalculateSequenceLocks(const CTransaction &tx, int flags, std::vector<int>* prevHeights, const CBlockIndex& block);

bool EvaluateSequenceLocks(const CBlockIndex& block, std::pair<int, int64_t> lockPair);
/**
 * Check if transaction is final per BIP 68 sequence numbers and can be included in a block.
 * Consensus critical. Takes as input a list of heights at which tx's inputs (in order) confirmed.
 */
bool SequenceLocks(const CTransaction &tx, int flags, std::vector<int>* prevHeights, const CBlockIndex& block);

/** Auxiliary functions for block validation (ideally should not be exposed) */

/**
 * Compute at which vout of the block's coinbase transaction the witness
 * commitment occurs, or -1 if not found.
 */
int GetWitnessCommitmentIndex(const CBlock& block);

#endif // BITCOIN_CONSENSUS_CONSENSUS_H
