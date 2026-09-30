#!/usr/bin/env python3
"""Read-only JSON interface to an operator-owned local Parano1d verifier.

This adapter is not itself a consensus verifier. It requires a local node
under the caller's control and never accepts a remote RPC address.
"""
import argparse
import ipaddress
import json
from pathlib import Path
import sys
import urllib.request
import urllib.parse


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rpc', required=True)
    commands = parser.add_subparsers(dest='command', required=True)
    receipt = commands.add_parser('receipt')
    receipt.add_argument('file', type=Path)
    right = commands.add_parser('right')
    right.add_argument('file', type=Path, help='JSON ObjectInfo with opening_hex')
    right.add_argument('--slot', required=True, type=int)
    right.add_argument('--creation-id', required=True, type=int)
    args = parser.parse_args()
    url = urllib.parse.urlsplit(args.rpc)
    try:
        loopback = ipaddress.ip_address(url.hostname or '').is_loopback
    except ValueError:
        loopback = False
    if not loopback or url.scheme != 'http' or url.username or url.password or url.query or url.fragment:
        raise ValueError('This adapter requires an explicit loopback HTTP address for your own verifier')

    def rpc(method, params):
        payload = json.dumps({'jsonrpc':'2.0','id':1,'method':'paranoid_'+method,'params':params}).encode()
        req = urllib.request.Request(args.rpc,data=payload,headers={'Content-Type':'application/json'})
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(req,timeout=120) as response:
            value=json.loads(response.read())
        if value.get('error'):
            raise ValueError(str(value['error']))
        return value['result']

    if args.command == 'receipt':
        # The node enforces the canonical receipt format and cryptographic checks.
        if args.file.stat().st_size > 1110624:
            raise ValueError('Receipt exceeds the v2 decoded size limit')
        raw=args.file.read_bytes()
        for _ in range(3):
            before=rpc('getChainInfo',[])
            checked=rpc('verifyObjectReceipt',[raw.hex()])
            after=rpc('getChainInfo',[])
            if before['best_hash']==after['best_hash']:
                break
        else:
            raise ValueError('Verifier tip changed repeatedly; retry')
        value={'kind':'historical_contract_call','verified':checked['valid'],
               'canonical_at_tip':after['best_hash'],'tip_height':after['height'],
               'finalized':after['height']-checked['height']>=18,
               'current_right_checked':False,'call':checked}
    else:
        opening=json.loads(args.file.read_text())['opening_hex']
        status=rpc('getObjectStatus',[opening,args.slot])
        live=(status['matches_opening'] and not status['slot']['empty']
              and status['slot']['creation_id']==args.creation_id)
        value={'kind':'current_contract_instance','matches_exact_instance':live,
               'tip_height':status['tip_height'],'next_call_height':status['next_call_height'],
               'active_authority':status['active_authority'],'terms':status['object'],'slot':status['slot'],
               'external_action_authorized':False}
    print(json.dumps(value,sort_keys=True))


if __name__=='__main__':
    try:
        main()
    except Exception as error:
        print(json.dumps({'verified':False,'error':str(error)}))
        sys.exit(1)
