from flask import Flask, request, g
from flask_restful import Resource, Api
from sqlalchemy import create_engine
from flask import jsonify
import json
import eth_account
import algosdk
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import scoped_session
from sqlalchemy.orm import load_only
from datetime import datetime
import math
import sys
import traceback

# TODO: make sure you implement connect_to_algo, send_tokens_algo, and send_tokens_eth
from send_tokens import connect_to_algo, connect_to_eth, send_tokens_algo, send_tokens_eth

from models import Base, Order, TX

engine = create_engine('sqlite:///orders.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)

app = Flask(__name__)

""" Pre-defined methods (do not need to change) """


@app.before_request
def create_session():
    g.session = scoped_session(DBSession)


@app.teardown_appcontext
def shutdown_session(response_or_exc):
    sys.stdout.flush()
    g.session.commit()
    g.session.remove()


def connect_to_blockchains():
    try:
        # If g.acl has not been defined yet, then trying to query it fails
        acl_flag = False
        g.acl
    except AttributeError as ae:
        acl_flag = True

    try:
        if acl_flag or not g.acl.status():
            # Define Algorand client for the application
            g.acl = connect_to_algo()
    except Exception as e:
        print("Trying to connect to algorand client again")
        print(traceback.format_exc())
        g.acl = connect_to_algo()

    try:
        icl_flag = False
        g.icl
    except AttributeError as ae:
        icl_flag = True

    try:
        if icl_flag or not g.icl.health():
            # Define the index client
            g.icl = connect_to_algo(connection_type='indexer')
    except Exception as e:
        print("Trying to connect to algorand indexer client again")
        print(traceback.format_exc())
        g.icl = connect_to_algo(connection_type='indexer')

    try:
        w3_flag = False
        g.w3
    except AttributeError as ae:
        w3_flag = True

    try:
        if w3_flag or not g.w3.isConnected():
            g.w3 = connect_to_eth()
    except Exception as e:
        print("Trying to connect to web3 again")
        print(traceback.format_exc())
        g.w3 = connect_to_eth()


""" End of pre-defined methods """

""" Helper Methods (skeleton code for you to implement) """


def log_message(message_dict):
    msg = json.dumps(message_dict)

    # TODO: Add message to the Log table
    log_obj = Log(message=json.dumps(d))
    g.session.add(log_obj)
    g.session.commit()


def get_algo_keys():
    # TODO: Generate or read (using the mnemonic secret)
    # the algorand public/private keys
    algo_sk, algo_pk = algodsk.generate_account();
    return algo_sk, algo_pk


def get_eth_keys(filename="eth_mnemonic.txt"):
    w3 = Web3()

    # TODO: Generate or read (using the mnemonic secret)
    # the ethereum public/private keys

    return eth_sk, eth_pk


def fill_order(order, txes=[]):
    # TODO:
    # Match orders (same as Exchange Server II)
    # Validate the order has a payment to back it (make sure the counterparty also made a payment)
    # Make sure that you end up executing all resulting transactions!

    pass


def execute_txes(txes):
    if txes is None:
        return True
    if len(txes) == 0:
        return True
    print(f"Trying to execute {len(txes)} transactions")
    print(f"IDs = {[tx['order_id'] for tx in txes]}")
    eth_sk, eth_pk = get_eth_keys()
    algo_sk, algo_pk = get_algo_keys()

    if not all(tx['platform'] in ["Algorand", "Ethereum"] for tx in txes):
        print("Error: execute_txes got an invalid platform!")
        print(tx['platform'] for tx in txes)

    algo_txes = [tx for tx in txes if tx['platform'] == "Algorand"]
    eth_txes = [tx for tx in txes if tx['platform'] == "Ethereum"]

    # TODO:
    #       1. Send tokens on the Algorand and eth testnets, appropriately
    #          We've provided the send_tokens_algo and send_tokens_eth skeleton methods in send_tokens.py
    #       2. Add all transactions to the TX table

    pass


# TC Check Signatures
def check_sig(payload, sig):
    json_payload = json.dumps(payload)
    result = False
    if (payload['platform'] == "Algorand"):
        if algosdk.util.verify_bytes(json_payload.encode('utf-8'), sig, payload['sender_pk']):
            result = True

    elif (payload['platform'] == "Ethereum"):
        eth_encoded_msg = eth_account.messages.encode_defunct(text=json_payload)
        if eth_account.Account.recover_message(eth_encoded_msg, signature=sig) == payload['sender_pk']:
            result = True
    return result


""" End of Helper methods"""


@app.route('/address', methods=['POST'])
def address():
    if request.method == "POST":
        content = request.get_json(silent=True)
        if 'platform' not in content.keys():
            print(f"Error: no platform provided")
            return jsonify("Error: no platform provided")
        if not content['platform'] in ["Ethereum", "Algorand"]:
            print(f"Error: {content['platform']} is an invalid platform")
            return jsonify(f"Error: invalid platform provided: {content['platform']}")

        if content['platform'] == "Ethereum":
            # Your code here
            return jsonify(eth_pk)
        if content['platform'] == "Algorand":
            # Your code here
            return jsonify(algo_pk)


@app.route('/trade', methods=['POST'])
def trade():
    print("In trade", file=sys.stderr)
    connect_to_blockchains()
    get_keys()
    if request.method == "POST":
        content = request.get_json(silent=True)
        columns = ["buy_currency", "sell_currency", "buy_amount", "sell_amount", "platform", "tx_id", "receiver_pk"]
        fields = ["sig", "payload"]
        error = False
        for field in fields:
            if not field in content.keys():
                print(f"{field} not received by Trade")
                error = True
        if error:
            print(json.dumps(content))
            return jsonify(False)

        error = False
        for column in columns:
            if not column in content['payload'].keys():
                print(f"{column} not received by Trade")
                error = True
        if error:
            print(json.dumps(content))
            return jsonify(False)

        # Your code here

        # 1. Check the signature
    payload = content['payload']
    sig = content["sig"]
    result = check_sig(payload, sig)
    # 2. Add the order to the table
    if result:
        order_obj = Order(sender_pk=payload['sender_pk'], receiver_pk=payload['receiver_pk'],
                          buy_currency=payload['buy_currency'], sell_currency=payload['sell_currency'],
                          buy_amount=payload['buy_amount'], sell_amount=payload['sell_amount'], signature=sig)
        g.session.add(order_obj)
        g.session.commit()

        # 3a. Check if the order is backed by a transaction equal to the sell_amount (this is new)
        acl = connect_to_algo('indexer')
        acl.search_transactions(payload['tx_id'])
        # 3b. Fill the order (as in Exchange Server II) if the order is valid
        existing = find_match(order_obj)
        if existing is not None:
            fill_order(order_obj, existing)
            return jsonify(True)
        # 4. Execute the transactions

    else:
        log_message(payload)
        return jsonify(False)
        # If all goes well, return jsonify(True). else return jsonify(False)
    return jsonify(True)


@app.route('/order_book')
def order_book():
    fields = ["buy_currency", "sell_currency", "buy_amount", "sell_amount", "signature", "tx_id", "receiver_pk",
              "sender_pk"]
    orders = g.session.query(Order).all()
    order_list = []
    for o in orders:
        order = {}
        order['sender_pk'] = o.sender_pk
        order['receiver_pk'] = o.receiver_pk
        order['buy_currency'] = o.buy_currency
        order['sell_currency'] = o.sell_currency
        order['buy_amount'] = o.buy_amount
        order['sell_amount'] = o.sell_amount
        order['signature'] = o.signature
        order['tx_id'] = o.tx_id
        order_list.append(order)
    result = {'data': order_list}
    return jsonify(result)


if __name__ == '__main__':
    app.run(port='5002')
