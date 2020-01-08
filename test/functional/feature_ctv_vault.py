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

from test_framework.messages import (FromHex, CTransaction)

from collections import defaultdict


BIP68_ERROR = 'non-BIP68-final (-26)'
SPENT_ERROR = "bad-txns-inputs-missingorspent (-25)"

class Vault:
    def __init__(self, data, node):
        self.node = node
        self.metadata = data['metadata']
        self.txns = data['program']
        self.utxo_spend_map = defaultdict(dict)
        self.withdrawals = []
        for tx in self.txns:
            tx['tx'] = FromHex(CTransaction(), tx['hex'])
            inp = tx['tx'].vin[0].prevout
            self.utxo_spend_map[inp][tx['label']] = tx
        self.state = list(filter(lambda tx: tx['label'] == 'vault_to_vault', self.txns))

    def create(self):
        txid = self.node.sendrawtransaction(self.txns[0]['hex'])
        assert_equal(txid, self.metadata['prevout']['hash'])

    def withdraw_step(self):
        self.node.sendrawtransaction(self.state.pop(0)['hex'])

    def freeze(self):
        for tx in filter(lambda tx: tx['label'] in ["to_cold", "vault_to_cold"], self.txns):
            try:
                self.node.sendrawtransaction(tx['hex'])
            except Exception as e:
                assert_equal(e.args[0], SPENT_ERROR)
    def move_deposits_hot(self):
        for tx in filter(lambda tx: tx['label'] in ["to_hot"], self.txns):
            try:
                self.node.sendrawtransaction(tx['hex'])
            except Exception as e:
                assert_equal(e.args[0], BIP68_ERROR)
                break



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
        vault.create()
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
