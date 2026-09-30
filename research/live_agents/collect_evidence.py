#!/usr/bin/env python3
"""Collect public experiment evidence without node databases or wallet files."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('run', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    source = Path(__file__).resolve().parent
    report = json.loads((args.run / 'report.json').read_text())
    if report['status'] != 'passed' or report.get('shutdown_errors'):
        raise ValueError('Collect only a completed, successfully stopped run')
    if report['script_sha256'] != digest(source / 'experiment.py'):
        raise ValueError('Experiment source changed since the run began')
    if args.output.exists():
        raise ValueError('Use a new evidence directory')
    args.output.mkdir(parents=True)
    (args.output / 'receipts').mkdir()
    shutil.copyfile(args.run / 'report.json', args.output / 'report.json')
    adapter = args.run / 'adapter-tests.json'
    if adapter.exists():
        checked = json.loads(adapter.read_text())
        if checked['adapter_sha256'] != digest(source / 'agent_view.py'):
            raise ValueError('Adapter source changed after testing')
        shutil.copyfile(adapter, args.output / 'adapter-tests.json')
    for permit in report['permits']:
        receipt = args.run / 'receipts' / (permit['txid'] + '.receipt')
        if digest(receipt) != permit['receipt_sha256']:
            raise ValueError('Receipt digest mismatch')
        shutil.copyfile(receipt, args.output / 'receipts' / receipt.name)
    binding = args.run / 'instance-binding.json'
    if binding.exists():
        checked = json.loads(binding.read_text())
        receipt = args.run / 'foreign-instance.receipt'
        if (checked['script_sha256'] != digest(source / 'check_instance_binding.py')
                or checked['receipt_sha256'] != digest(receipt)):
            raise ValueError('Instance-binding evidence digest mismatch')
        shutil.copyfile(binding, args.output / binding.name)
        shutil.copyfile(receipt, args.output / 'receipts' / receipt.name)
    originals = [source / name for name in ('experiment.py', 'baseline.py', 'agent_view.py',
                                            'check_instance_binding.py', 'collect_evidence.py')]
    originals.extend(source.parents[1] / 'scripts' / name for name in
                     ('live_v2_contract_scenario.py', 'live_two_miner_fork_reorg_scenario.py'))
    manifest = {'source_head': report['source_head'],
                'source_files': {str(p.relative_to(source.parents[1])): digest(p) for p in originals},
                'evidence_files': {str(p.relative_to(args.output)): digest(p)
                                   for p in sorted(args.output.rglob('*')) if p.is_file()}}
    (args.output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps({'output': str(args.output), 'permit_receipts': len(report['permits']),
                      'additional_receipts': int(binding.exists()),
                      'bytes': sum(p.stat().st_size for p in args.output.rglob('*') if p.is_file())}))


if __name__ == '__main__':
    main()
