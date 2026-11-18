import os
import sqlite3
import tempfile
import unittest

from app.server import create_app


class ApiTests(unittest.TestCase):
    def setUp(self):
        fd, self.path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self.client = create_app(db_path=self.path, secret_key="teste").test_client()

    def tearDown(self):
        os.remove(self.path)

    def reg(self, u="ana", p="uma-senha-bem-longa"):
        return self.client.post("/register", json={"username": u, "password": p})

    def test_cadastro_ok_e_banco_sem_texto_puro(self):
        self.assertEqual(self.reg().status_code, 201)
        row = sqlite3.connect(self.path).execute("SELECT password_hash FROM users").fetchone()[0]
        self.assertTrue(row.startswith("$argon2id$"))
        self.assertNotIn("uma-senha-bem-longa", row)

    def test_login_correto(self):
        self.reg()
        r = self.client.post("/login", json={"username": "ana", "password": "uma-senha-bem-longa"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(self.client.get("/me").status_code, 200)

    def test_login_senha_incorreta(self):
        self.reg()
        r = self.client.post("/login", json={"username": "ana", "password": "senha-errada-123"})
        self.assertEqual(r.status_code, 401)
        self.assertEqual(self.client.get("/me").status_code, 401)

    def test_mensagem_igual_para_usuario_inexistente(self):
        self.reg()
        a = self.client.post("/login", json={"username": "ana", "password": "senha-errada-123"})
        b = self.client.post("/login", json={"username": "ninguem", "password": "senha-errada-123"})
        self.assertEqual((a.status_code, a.get_json()), (b.status_code, b.get_json()))

    def test_usuario_duplicado_case_insensitive(self):
        self.reg("ana")
        self.assertEqual(self.reg("ANA").status_code, 409)

    def test_senha_fraca_rejeitada(self):
        self.assertEqual(self.reg(p="123").status_code, 400)

    def test_sql_injection_no_login_nao_autentica(self):
        self.reg()
        r = self.client.post("/login", json={"username": "ana' OR '1'='1", "password": "x' OR '1'='1"})
        self.assertEqual(r.status_code, 401)

    def test_entrada_nao_json_ou_tipos_errados(self):
        self.assertEqual(self.client.post("/login", data="lixo").status_code, 401)
        self.assertEqual(self.client.post("/login", json={"username": 1, "password": []}).status_code, 401)

    def test_logout_encerra_sessao(self):
        self.reg()
        self.client.post("/login", json={"username": "ana", "password": "uma-senha-bem-longa"})
        self.client.post("/logout")
        self.assertEqual(self.client.get("/me").status_code, 401)


if __name__ == "__main__":
    unittest.main()
