#!/usr/bin/env python3
"""Benchmark script for Argon2 derived key parameters used by CryptoEngine."""
import time
from core.crypto.engine import ARGON2_PARAMS, CryptoEngine
from argon2.low_level import hash_secret_raw, Type

def bench_rounds(password=b"password", rounds=3):
    params = ARGON2_PARAMS.copy()
    for t in range(1, 6):
        params['time_cost'] = t
        start = time.time()
        hash_secret_raw(secret=password, salt=b"0"*16,
                        time_cost=params['time_cost'],
                        memory_cost=params['memory_cost'],
                        parallelism=params['parallelism'],
                        hash_len=params['hash_len'],
                        type=Type.ID)
        elapsed = time.time() - start
        print(f"time_cost={t} took {elapsed:.3f}s")

if __name__ == '__main__':
    print("Argon2 parameter benchmark (varying time_cost)")
    bench_rounds()
