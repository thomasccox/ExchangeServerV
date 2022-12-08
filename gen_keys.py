#!/usr/bin/python3

from algosdk import mnemonic
from algosdk import account
from web3 import Web3
from send_tokens import connect_to_eth
"""
algo_sk, algo_pk = account.generate_account()
print(algo_sk)
print(algo_pk)
mn = mnemonic.from_private_key(algo_sk)
print(mn)
maximum there honey circle slogan shiver auto chronic sphere base hobby repeat success glow trash trophy install rain coast proud country hurry glow absorb bicycle
"""
#w3 = connect_to_eth()
w3 = Web3()
w3.eth.account.enable_unaudited_hdwallet_features()
acct,mnemonic_secret = w3.eth.account.create_with_mnemonic()
print(mnemonic_secret)