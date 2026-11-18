"""Hash de senhas com Argon2id e política de senhas (Entrega 2).

Biblioteca: `cryptography` (cryptography.hazmat.primitives.kdf.argon2),
que usa a implementação do OpenSSL. NÃO implementamos algoritmo próprio.

Formato armazenado (PHC string; o salt já vai embutido):
    $argon2id$v=19$m=47104,t=2,p=1$<salt_b64>$<hash_b64>

Parâmetros (referência: OWASP ASVS 5.0 req. 11.4.2 -> Argon2id com m >= 46 MiB, t = 1;
usamos t = 2 para folga):
    m = 47104 KiB (46 MiB) | t = 2 iterações | p = 1 lane | salt 16 B | hash 32 B
"""
import base64
import os
import unicodedata

from cryptography.exceptions import InvalidKey
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

MEMORY_KIB = 47104
ITERATIONS = 2
LANES = 1
SALT_LEN = 16
HASH_LEN = 32
ARGON2_VERSION = 19

MIN_LEN = 8        # ASVS 6.2.1 (L1): mínimo de 8; 15 é fortemente recomendado
MAX_LEN = 128      # limita custo de CPU/memória por requisição
# Lista mínima de didática. Em produção: base de senhas vazadas (ASVS 6.2.12).
SENHAS_COMUNS = {
    "12345678", "123456789", "1234567890", "password", "password1",
    "qwertyuiop", "11111111", "abcd1234", "senha123", "iloveyou",
    "admin123", "letmein123", "123123123", "mudar123", "brasil123",
}


class PasswordPolicyError(ValueError):
    """Senha rejeitada pela política."""


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode().rstrip("=")


def _b64d(text: str) -> bytes:
    return base64.b64decode(text + "=" * (-len(text) % 4))


def _normalize(password: str) -> bytes:
    # NFKC: mesma senha digitada em formas Unicode diferentes gera o mesmo hash.
    return unicodedata.normalize("NFKC", password).encode("utf-8")


def validate_password(password: str) -> None:
    """ASVS 6.2.1 (tamanho) e 6.2.5 (SEM regras de composição obrigatórias)."""
    if not isinstance(password, str):
        raise PasswordPolicyError("Senha inválida.")
    if len(password) < MIN_LEN:
        raise PasswordPolicyError(f"A senha deve ter no mínimo {MIN_LEN} caracteres (recomendado: 15 ou mais).")
    if len(password) > MAX_LEN:
        raise PasswordPolicyError(f"A senha deve ter no máximo {MAX_LEN} caracteres.")
    if password.lower() in SENHAS_COMUNS:
        raise PasswordPolicyError("Senha muito comum. Escolha outra.")


def hash_password(password: str, *, salt: bytes | None = None) -> str:
    """Gera o hash Argon2id com salt aleatório (os.urandom) único por senha."""
    salt = salt if salt is not None else os.urandom(SALT_LEN)
    kdf = Argon2id(salt=salt, length=HASH_LEN, iterations=ITERATIONS,
                   lanes=LANES, memory_cost=MEMORY_KIB)
    digest = kdf.derive(_normalize(password))
    return (f"$argon2id$v={ARGON2_VERSION}$m={MEMORY_KIB},t={ITERATIONS},p={LANES}"
            f"${_b64e(salt)}${_b64e(digest)}")


def _parse(phc: str):
    parts = phc.split("$")
    # ['', 'argon2id', 'v=19', 'm=..,t=..,p=..', salt, hash]
    if len(parts) != 6 or parts[1] != "argon2id":
        raise ValueError("formato de hash desconhecido")
    params = dict(item.split("=") for item in parts[3].split(","))
    return int(params["m"]), int(params["t"]), int(params["p"]), _b64d(parts[4]), _b64d(parts[5])


def verify_password(password: str, phc: str) -> bool:
    """Comparação segura: `Argon2id.verify` da biblioteca usa comparação em tempo constante."""
    try:
        m, t, p, salt, expected = _parse(phc)
        kdf = Argon2id(salt=salt, length=len(expected), iterations=t, lanes=p, memory_cost=m)
        kdf.verify(_normalize(password), expected)
        return True
    except (InvalidKey, ValueError, KeyError):
        return False


def needs_rehash(phc: str) -> bool:
    """True se o hash foi gerado com parâmetros mais fracos que os atuais (permite migrar no login)."""
    try:
        m, t, p, _, _ = _parse(phc)
    except ValueError:
        return True
    return (m, t, p) != (MEMORY_KIB, ITERATIONS, LANES)


# Hash "isca": usado quando o usuário não existe, para o tempo de resposta
# ser parecido e dificultar enumeração de usuários.
DUMMY_HASH = hash_password("senha-isca-nao-utilizada")
