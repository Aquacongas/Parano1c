#!/usr/bin/env python3
"""Test identical terms on a different instance against an untouched grant cursor.

Run inside the active experiment's network namespace with NOID_V2_LIVE_DIR set.
The main experiment must have recorded its foreign-instance call already.
"""
import hashlib
import json
from types import SimpleNamespace

import experiment as test


def main():
    report = json.loads((test.BASE / 'report.json').read_text())
    enrolled = report['enrollment']
    issuer = SimpleNamespace(rpc_port=26601)
    verifier = SimpleNamespace(rpc_port=26611)
    encoded = test.rpc(issuer, 'exportObjectReceipt',
                       [enrolled['opening']['opening_hex'], report['foreign_instance']['txid']])
    checked = test.rpc(verifier, 'verifyObjectReceipt', [encoded])
    assert checked['valid']
    assert checked['original']['opening_hex'] == enrolled['opening']['opening_hex']
    page = test.receipt_page(encoded)
    assert (page['input_slot'], page['input_creation']) != (
        enrolled['slot']['slot_index'], enrolled['slot']['creation_id'])
    assert not (test.BASE / 'instance-binding-probe').exists(), 'Use a fresh probe'
    gateway = test.Gateway('instance-binding-probe', verifier,
                          enrolled['opening'], enrolled['slot'])
    try:
        try:
            gateway.observe(encoded)
        except test.Denied as error:
            assert str(error) == 'outside_enrolled_instance_lineage'
            result = {'status': 'passed', 'network_valid': True,
                      'original_opening_equals_enrolled_opening': True,
                      'input_matches_enrolled_instance': False,
                      'gateway_result': str(error), 'txid': checked['txid'],
                      'script_sha256': test.live.sha256(__file__),
                      'receipt_sha256': hashlib.sha256(bytes.fromhex(encoded)).hexdigest()}
        else:
            raise AssertionError('Unenrolled instance accepted')
    finally:
        gateway.close()
    (test.BASE / 'foreign-instance.receipt').write_bytes(bytes.fromhex(encoded))
    test.write_json(test.BASE / 'instance-binding.json', result)
    print(json.dumps(result))


if __name__ == '__main__':
    main()
