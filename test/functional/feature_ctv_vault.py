#!/usr/bin/env python3
# Copyright (c) 2015-2019 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test (CheckTemplateVerify)
"""

from test_framework.blocktools import create_coinbase, create_block, create_transaction, add_witness_commitment
from test_framework.messages import CTransaction, CTxOut, CTxIn, CTxInWitness, COutPoint, sha256
from test_framework.mininode import P2PInterface
from test_framework.script import CScript, OP_TRUE, OP_CHECKTEMPLATEVERIFY, OP_FALSE
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
        assert_equal,
        hex_str_to_bytes,
        connect_nodes
        )
import random
from io import BytesIO
from test_framework.address import script_to_p2sh

CHECKTEMPLATEVERIFY_ERROR = "non-mandatory-script-verify-flag (Script failed an OP_CHECKTEMPLATEVERIFY operation)"


def parse_print_tx(htx):
    tx = CTransaction()
    tx.deserialize(BytesIO(hex_str_to_bytes(htx)))
    print(tx)

class Vault:
    def __init__(self, data, node):
        self.create_tx = data["metadata"]["create_tx"]
        self.prevout = data["metadata"]["prevout"]
        self.data = data
        self.node = node
        self.walk = data
        self.withdrawals = []
        self.withdrawn = []
    def create(self):
        parse_print_tx(self.create_tx)
        txid = self.node.sendrawtransaction(self.create_tx)
        assert_equal(txid, self.prevout["hash"])
        return txid

    def withdraw_step(self):
        step = self.walk["step"]
        parse_print_tx(step)
        self.node.sendrawtransaction(step)
        self.withdrawals.append(self.walk["children"]["withdrawal"])
        self.freeze_tx = self.walk["children"]["sub_vault"]["to_cold"]
        self.walk = self.walk["children"]["sub_vault"]["next"]

    def freeze_vault(self):
        for child in self.withdrawals:
            self.node.sendrawtransaction(child["to_cold"])
    def freeze_past_withdrawals(self):
        self.node.sendrawtransaction(self.freeze_tx)
    def freeze(self):
        self.freeze_vault()
        self.freeze_past_withdrawals()
    def move_deposits_hot(self):
        self.withdrawn.append(self.withdrawals.pop(0))
        self.node.sendrawtransaction(self.withdrawn[-1]["to_hot"])


class CheckTemplateVerifyTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.extra_args = [['-whitelist=127.0.0.1', '-par=1']]*2  # Use only one script thread to get the exact reject reason for testing
        self.setup_clean_chain = True
        self.rpc_timeout = 120

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
    def get_block(self, txs):
        self.tip    = self.nodes[0].getbestblockhash()
        self.height = self.nodes[0].getblockcount()
        block = create_block(int(self.tip, 16), create_coinbase(self.height))
        block.vtx.extend(txs)
        add_witness_commitment(block)
        block.hashMerkleRoot = block.calc_merkle_root()
        block.solve()
        return block.serialize(True).hex(), block.hash
    def add_block(self, txs):
        block, h = self.get_block(txs)
        self.nodes[0].submitblock(block)
        assert_equal(self.nodes[0].getbestblockhash(), h)
        return h
    def fail_block(self, txs, cause = CHECKTEMPLATEVERIFY_ERROR):
        block, h = self.get_block(txs)
        assert_equal(self.nodes[0].submitblock(block), cause)
        assert_equal(self.nodes[0].getbestblockhash(), self.tip)

    def run_test(self):

        self.nodes[0].add_p2p_connection(P2PInterface())
        connect_nodes(self.nodes[0], 1)
        connect_nodes(self.nodes[1], 0)

        BLOCKS = 110
        self.log.info("Mining %d blocks for mature coinbases", BLOCKS)
        self.coinbase_txids = [self.nodes[0].getblock(b)['tx'][0] for b in self.nodes[0].generate(BLOCKS)]

        self.log.info("Creating setup transactions")

        vault = Vault(self.nodes[0].create_ctv_vault(0.1, 20, 1, 1), self.nodes[0])
        self.log.info("Created vault at: " + vault.create())
        self.nodes[0].generate(1)
        self.log.info("withdraw funds")
        step = vault.withdraw_step()
        self.log.info(step)
        self.nodes[0].generate(1)
        self.log.info("withdraw funds 2")
        vault.withdraw_step()
        self.log.info("moving to hot")
        vault.move_deposits_hot()
        self.nodes[0].generate(1)
        self.log.info("Freezing funds")
        vault.freeze()
        self.nodes[0].generate(1)





if __name__ == '__main__':
    CheckTemplateVerifyTest().main()
