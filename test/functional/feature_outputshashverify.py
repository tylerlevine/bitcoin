#!/usr/bin/env python3
# Copyright (c) 2015-2019 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test (CHECKOUTPUTSHASHVERIFY)
"""

from test_framework.blocktools import create_coinbase, create_block, create_transaction, add_witness_commitment
from test_framework.messages import CTransaction, msg_block, ToHex, CTxOut, CTxIn, CTxInWitness, COutPoint
from test_framework.mininode import P2PInterface
from test_framework.script import CScript, OP_TRUE, OP_RETURN, OP_CHECKLOCKTIMEVERIFY, OP_DROP, CScriptNum, OP_CHECKOUTPUTSHASHVERIFY, taproot_construct, hash256, hash160, OP_HASH160, OP_EQUAL
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    hex_str_to_bytes,
)
import random
from io import BytesIO
from test_framework.key import ECKey
from test_framework.address import program_to_witness, script_to_p2sh

OUTPUTSHASHVERIFY_ERROR = "non-mandatory-script-verify-flag (Script failed an OP_OUTPUTSHASHVERIFY operation)"
def random_bytes(n):
    return bytes(random.getrandbits(8) for i in range(n))
def random_fake_script():
    return CScript([OP_CHECKOUTPUTSHASHVERIFY, random_bytes(32)])
def random_real_outputs_and_script(n):
    outputs = [CTxOut((x+1)*100, CScript(bytes([OP_RETURN, 0x20]) + random_bytes(32))) for x in range(n)]
    return outputs, CScript(bytes([OP_CHECKOUTPUTSHASHVERIFY, 0x20]) + hash256(b"".join(o.serialize() for o in outputs)))

def get_taproot_bech32(spk):
    return program_to_witness(1, spk[2:])
class COSHVTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.extra_args = [['-whitelist=127.0.0.1', '-par=1']]  # Use only one script thread to get the exact reject reason for testing
        self.setup_clean_chain = True
        self.rpc_timeout = 120

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        self.nodes[0].add_p2p_connection(P2PInterface())

        self.log.info("Mining %d blocks", 100)
        self.coinbase_txids = [self.nodes[0].getblock(b)['tx'][0] for b in self.nodes[0].generate(110)]

        outputs, script = random_real_outputs_and_script(10)
        sec1 = ECKey()
        sec1.generate()
        pubkey1 = sec1.get_pubkey()
        taproot, tweak, controls = taproot_construct(pubkey1, [script])
        # Add some fee satoshis
        amount = (sum(out.nValue for out in outputs)+200*500) /100e6

        # Fund this taproot address into two UTXOs
        spendtx = create_transaction(self.nodes[0], self.coinbase_txids[0],
                get_taproot_bech32(taproot), amount=amount)
        spendtx2 = create_transaction(self.nodes[0], self.coinbase_txids[1],
                script_to_p2sh(CScript([OP_TRUE])), amount=amount)
        print(spendtx2.serialize().hex())
        outpoint = COutPoint(int(spendtx.rehash(),16), 0)
        outpoint2 = COutPoint(int(spendtx2.rehash(),16), 0)

        tip = self.nodes[0].getbestblockhash()
        height = self.nodes[0].getblockcount()
        block = create_block(int(tip, 16), create_coinbase(height))
        block.vtx.append(spendtx)
        block.vtx.append(spendtx2)
        block.hashMerkleRoot = block.calc_merkle_root()
        block.solve()
        self.nodes[0].submitblock(block.serialize(False).hex())
        assert_equal(self.nodes[0].getbestblockhash(), block.hash)


        # Test sendrawtransaction
        coshvTx = CTransaction()
        coshvTx.nVersion = 2
        coshvTx.vin += [CTxIn(outpoint)]
        coshvTx.vout += outputs
        coshvTx.wit.vtxinwit +=  [CTxInWitness()]
        coshvTx.wit.vtxinwit[0].scriptWitness.stack = [script, controls[script]]
        assert_equal(self.nodes[0].sendrawtransaction(coshvTx.serialize().hex(), 0), coshvTx.rehash())



        # Now we verify that a block with this transaction is also valid
        tip = self.nodes[0].getbestblockhash()
        height = self.nodes[0].getblockcount()


        block = create_block(int(tip, 16), create_coinbase(height))
        block.vtx.append(coshvTx)
        block.hashMerkleRoot = block.calc_merkle_root()
        add_witness_commitment(block)
        block.solve()
        self.nodes[0].submitblock(block.serialize(True).hex())
        assert_equal(self.nodes[0].getbestblockhash(), block.hash)

        # Reset tip
        self.nodes[0].invalidateblock(block.hash)

        # Show any modification will break the validity
        block = create_block(int(tip, 16), create_coinbase(height))
        coshvTx_mutated_amount = coshvTx
        coshvTx_mutated_amount.vout[0].nValue += 1
        coshvTx_mutated_amount.rehash()
        block.vtx.append(coshvTx_mutated_amount)
        block.hashMerkleRoot = block.calc_merkle_root()
        add_witness_commitment(block)
        block.solve()
        assert_equal(self.nodes[0].submitblock(block.serialize(True).hex()), OUTPUTSHASHVERIFY_ERROR)
        assert_equal(self.nodes[0].getbestblockhash(), tip)


        # Now show that only one input allowed
        tip = self.nodes[0].getbestblockhash()
        height = self.nodes[0].getblockcount()

        block = create_block(int(tip, 16), create_coinbase(height))
        coshvTx_two_inputs = coshvTx
        coshvTx_two_inputs.vin += [CTxIn(outpoint2, b"\x01\x51")]
        coshvTx_two_inputs.rehash()
        block.vtx.append(coshvTx_two_inputs)
        block.hashMerkleRoot = block.calc_merkle_root()
        add_witness_commitment(block)
        block.solve()
        assert_equal(self.nodes[0].submitblock(block.serialize(True).hex()), OUTPUTSHASHVERIFY_ERROR)
        assert_equal(self.nodes[0].getbestblockhash(), tip)

        coshvTx_two_inputs.vin.pop(0)
        coshvTx_two_inputs.wit.vtxinwit.pop(0)

        # Second UTXO was actually spendable
        block = create_block(int(tip, 16), create_coinbase(height))
        spendtx = CTransaction()
        spendtx.vin = [CTxIn(outpoint2, b"\x01\x51")]
        spendtx.vout = coshvTx.vout
        spendtx.rehash()
        block.vtx.append(spendtx)
        block.hashMerkleRoot = block.calc_merkle_root()
        block.solve()
        self.nodes[0].sendrawtransaction(spendtx.serialize().hex())
        self.nodes[0].submitblock(block.serialize(True).hex())
        assert_equal(self.nodes[0].getbestblockhash(), block.hash)


if __name__ == '__main__':
    COSHVTest().main()
