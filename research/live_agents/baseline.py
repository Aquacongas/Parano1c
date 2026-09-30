#!/usr/bin/env python3
"""Control experiment: duplicated counters versus one transactional quota.

These are reference constructions, not measurements of another product.
"""
import argparse
import concurrent.futures
import json
from pathlib import Path
import sqlite3
import tempfile


def client(args):
    path, attempts = args
    accepted = 0
    with sqlite3.connect(path, timeout=60) as db:
        for _ in range(attempts):
            db.execute('BEGIN IMMEDIATE')
            remaining = db.execute('SELECT remaining FROM quota').fetchone()[0]
            if remaining:
                db.execute('UPDATE quota SET remaining=remaining-1')
                accepted += 1
            db.commit()
    return accepted


def initialize(path, quota):
    with sqlite3.connect(path) as db:
        db.execute('PRAGMA journal_mode=WAL')
        db.execute('CREATE TABLE quota(remaining INTEGER NOT NULL CHECK(remaining>=0))')
        db.execute('INSERT INTO quota VALUES(?)',(quota,))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',type=Path,required=True)
    args=parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='live-agents-control-') as temp:
        base=Path(temp)
        paths=[base/f'copy-{i}.sqlite' for i in range(8)]
        shared=base/'shared.sqlite'
        for p in paths+[shared]: initialize(p,10)
        with concurrent.futures.ProcessPoolExecutor(max_workers=8) as pool:
            copied=list(pool.map(client,[(str(p),10) for p in paths]))
            central=list(pool.map(client,[(str(shared),10)]*8))
        assert sum(copied)==80 and sum(central)==10
        result={'clients':8,'attempts_per_client':10,'initial_quota':10,
                'copied_stores':{'accepted':sum(copied),'by_client':copied},
                'shared_transactional_store':{'accepted':sum(central),'by_client':central},
                'interpretation':'A conventional shared database correctly enforces a global quota. Independent copies do not.'}
        args.out.parent.mkdir(parents=True,exist_ok=True)
        args.out.write_text(json.dumps(result,indent=2)+'\n')
        print(json.dumps(result))


if __name__=='__main__': main()
