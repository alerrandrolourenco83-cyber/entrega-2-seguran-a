"""Demonstração para o vídeo/evidências da Entrega 2.  Uso:  python -m scripts.demo"""
import os
import tempfile

from app import auth, db, security


def main():
    path = os.path.join(tempfile.mkdtemp(), "demo.db")
    conn = db.connect(path)
    senha = "correta-cavalo-bateria-grampo"

    print("1) CADASTRO: usuário 'maria' com senha em texto puro:", repr(senha))
    auth.register(conn, "maria", senha)

    print("\n2) O QUE FICA NO BANCO (nunca a senha):")
    for r in conn.execute("SELECT id, username, password_hash FROM users"):
        print("  ", dict(r))

    print("\n3) SALT ÚNICO: mesma senha, outro usuário -> hash diferente")
    auth.register(conn, "joao", senha)
    h = [r[0] for r in conn.execute("SELECT password_hash FROM users ORDER BY id")]
    print("   hashes iguais?", h[0] == h[1])

    print("\n4) LOGIN CORRETO  ->", "ACEITO" if auth.login(conn, "maria", senha) else "NEGADO")
    print("   LOGIN INCORRETO ->", "ACEITO" if auth.login(conn, "maria", "senha-errada-1234") else "NEGADO")
    print("   USUÁRIO INEXISTENTE ->", "ACEITO" if auth.login(conn, "fantasma", senha) else "NEGADO")

    print("\n5) POLÍTICA DE SENHA:")
    for tentativa in ["123", "password1", "a" * 129]:
        try:
            auth.register(conn, "teste", tentativa)
        except security.PasswordPolicyError as e:
            print(f"   {tentativa[:12]!r:>14} -> rejeitada: {e}")

    print("\n6) ADULTERAÇÃO DO HASH no banco -> login deixa de funcionar")
    conn.execute("UPDATE users SET password_hash = substr(password_hash,1,length(password_hash)-3)||'AAA' WHERE username='maria'")
    conn.commit()
    print("   LOGIN com senha certa e hash adulterado ->", "ACEITO" if auth.login(conn, "maria", senha) else "NEGADO")


if __name__ == "__main__":
    main()
