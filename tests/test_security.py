import unittest

from app import security as s


class HashTests(unittest.TestCase):
    def test_formato_phc_com_parametros(self):
        h = s.hash_password("uma senha longa e boa")
        self.assertTrue(h.startswith("$argon2id$v=19$m=47104,t=2,p=1$"))
        self.assertNotIn("uma senha longa e boa", h)

    def test_salt_unico_mesma_senha_hashes_diferentes(self):
        self.assertNotEqual(s.hash_password("mesma-senha-123"), s.hash_password("mesma-senha-123"))

    def test_senha_correta_e_incorreta(self):
        h = s.hash_password("correta-horse-battery")
        self.assertTrue(s.verify_password("correta-horse-battery", h))
        self.assertFalse(s.verify_password("errada-horse-battery", h))

    def test_hash_adulterado_nao_valida(self):
        h = s.hash_password("correta-horse-battery")
        adulterado = h[:-3] + ("AAA" if not h.endswith("AAA") else "BBB")
        self.assertFalse(s.verify_password("correta-horse-battery", adulterado))

    def test_hash_malformado_nao_levanta_excecao(self):
        for lixo in ["", "abc", "$argon2id$", "$bcrypt$a$b$c$d"]:
            self.assertFalse(s.verify_password("qualquer-senha", lixo))

    def test_needs_rehash(self):
        h = s.hash_password("senha-para-rehash")
        self.assertFalse(s.needs_rehash(h))
        self.assertTrue(s.needs_rehash(h.replace("m=47104", "m=1024")))

    def test_normalizacao_unicode(self):
        h = s.hash_password("sênha-çom-acentos")  # forma composta
        self.assertTrue(s.verify_password("se\u0302nha-c\u0327om-acentos", h))  # forma decomposta


class PolicyTests(unittest.TestCase):
    def test_curta_rejeitada(self):
        with self.assertRaises(s.PasswordPolicyError):
            s.validate_password("1234567")

    def test_comum_rejeitada(self):
        with self.assertRaises(s.PasswordPolicyError):
            s.validate_password("Password1")

    def test_longa_demais_rejeitada(self):
        with self.assertRaises(s.PasswordPolicyError):
            s.validate_password("a" * 129)

    def test_sem_regra_de_composicao(self):  # ASVS 6.2.5
        s.validate_password("apenas minusculas e espacos")  # não deve levantar


if __name__ == "__main__":
    unittest.main()
