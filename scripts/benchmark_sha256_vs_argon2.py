"""Por que SHA-256 isolado NÃO serve para senhas?  Uso:  python -m scripts.benchmark_sha256_vs_argon2

Mede quantas tentativas por segundo um atacante (1 núcleo de CPU) consegue contra cada esquema.
GPUs/ASICs multiplicam o número de SHA-256 por MILHARES; Argon2id exige 46 MiB de memória por tentativa.
"""
import hashlib
import time

from app import security


def taxa(fn, segundos=1.0):
    n, fim = 0, time.perf_counter() + segundos
    while time.perf_counter() < fim:
        fn()
        n += 1
    return n / segundos


def main():
    sha = taxa(lambda: hashlib.sha256(b"senha-candidata").digest())
    arg = taxa(lambda: security.hash_password("senha-candidata"), segundos=2.0)
    print(f"SHA-256 (sem salt, sem custo): {sha:>14,.0f} tentativas/s (1 núcleo)")
    print(f"Argon2id (m=46MiB, t=2, p=1) : {arg:>14,.1f} tentativas/s (1 núcleo)")
    print(f"Razão: SHA-256 é ~{sha/arg:,.0f}x mais rápido de atacar.")
    print("\nSHA-256 de 'senha123' (igual para TODO usuário, vulnerável a rainbow table):")
    print(" ", hashlib.sha256(b"senha123").hexdigest())


if __name__ == "__main__":
    main()
