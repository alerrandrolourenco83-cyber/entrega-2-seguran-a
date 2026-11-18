"""Regras de cadastro e login (independentes do Flask: facilita testes e reuso)."""
import re
import sqlite3

from . import security

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")


class UsernameError(ValueError):
    pass


class UserExistsError(Exception):
    pass


def register(conn: sqlite3.Connection, username: str, password: str) -> int:
    if not isinstance(username, str) or not USERNAME_RE.match(username):
        raise UsernameError("Usuário deve ter 3-32 caracteres: letras, números, _ . -")
    security.validate_password(password)
    phc = security.hash_password(password)
    try:
        cur = conn.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, phc))
        conn.commit()
    except sqlite3.IntegrityError as exc:
        raise UserExistsError() from exc
    return cur.lastrowid


def login(conn: sqlite3.Connection, username: str, password: str) -> int | None:
    """Retorna o id do usuário se as credenciais forem válidas; senão None.

    Usuário inexistente e senha errada têm o MESMO resultado e tempo similar.
    """
    if not isinstance(username, str) or not isinstance(password, str) or len(password) > security.MAX_LEN:
        return None
    row = conn.execute("SELECT id, password_hash FROM users WHERE username = ?", (username,)).fetchone()
    stored = row["password_hash"] if row else security.DUMMY_HASH
    ok = security.verify_password(password, stored)
    if not (row and ok):
        return None
    if security.needs_rehash(stored):  # migração transparente de parâmetros
        conn.execute("UPDATE users SET password_hash = ? WHERE id = ?",
                     (security.hash_password(password), row["id"]))
        conn.commit()
    return row["id"]
