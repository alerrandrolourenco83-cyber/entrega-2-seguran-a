"""API Flask mínima: /register, /login, /me, /logout.

Execução (desenvolvimento):  python -m app.server
"""
import os
import secrets

from flask import Flask, jsonify, request, session
from werkzeug.exceptions import HTTPException

from . import auth, db, security


def create_app(db_path: str | None = None, secret_key: str | None = None) -> Flask:
    app = Flask(__name__)
    key = secret_key or os.environ.get("SECRET_KEY")
    if not key:  # segredo nunca fica no código; sem env, gera um aleatório só para esta execução
        key = secrets.token_hex(32)
        app.logger.warning("SECRET_KEY não definida: usando chave temporária (sessões somem ao reiniciar).")
    app.config.update(
        SECRET_KEY=key,
        DATABASE_PATH=db_path or os.environ.get("DATABASE_PATH", "usuarios.db"),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        MAX_CONTENT_LENGTH=16 * 1024,
    )

    def conn():
        return db.connect(app.config["DATABASE_PATH"])

    def body():
        data = request.get_json(silent=True)
        return data if isinstance(data, dict) else {}

    @app.post("/register")
    def register():
        data = body()
        c = conn()
        try:
            uid = auth.register(c, data.get("username"), data.get("password"))
        except (auth.UsernameError, security.PasswordPolicyError) as exc:
            return jsonify(error=str(exc)), 400
        except auth.UserExistsError:
            return jsonify(error="Não foi possível concluir o cadastro com esses dados."), 409
        finally:
            c.close()
        return jsonify(id=uid, username=data["username"]), 201

    @app.post("/login")
    def login():
        data = body()
        c = conn()
        try:
            uid = auth.login(c, data.get("username"), data.get("password"))
        finally:
            c.close()
        if uid is None:  # mensagem genérica: não revela se o usuário existe
            return jsonify(error="Usuário ou senha inválidos."), 401
        session.clear()
        session["uid"] = uid
        return jsonify(ok=True)

    @app.get("/me")
    def me():
        if "uid" not in session:
            return jsonify(error="Não autenticado."), 401
        return jsonify(uid=session["uid"])

    @app.post("/logout")
    def logout():
        session.clear()
        return jsonify(ok=True)

    @app.errorhandler(Exception)
    def erro_generico(exc):  # ASVS 16.5.1: sem stack trace para o cliente
        if isinstance(exc, HTTPException):
            return jsonify(error=exc.name), exc.code
        app.logger.exception("Erro inesperado")
        return jsonify(error="Erro interno."), 500

    return app


if __name__ == "__main__":
    # Escuta só em localhost por padrão (reduz exposição). Para o lab da Entrega 3, mude conscientemente.
    create_app().run(host=os.environ.get("HOST", "127.0.0.1"), port=int(os.environ.get("PORT", "5000")))
