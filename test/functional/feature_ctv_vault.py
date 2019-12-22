#!/usr/bin/env python3
# Copyright (c) 2015-2019 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test (CheckTemplateVerify)
"""

from test_framework.mininode import P2PInterface
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
        assert_equal,
        connect_nodes
        )




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
        txid = self.node.sendrawtransaction(self.create_tx)
        assert_equal(txid, self.prevout["hash"])

    def withdraw_step(self):
        step = self.walk["step"]
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
        vault.withdraw_step()
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
