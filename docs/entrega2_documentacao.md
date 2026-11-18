<!-- CAPA (ABNT): UNIVERSIDADE TIRADENTES · Curso: Sistemas de Informação/ADS · Disciplina: Segurança da Informação
     Docente: Profa. Ma. Ana Carla do Nascimento Santos · Título: Hash e autenticação segura · Aluno(s): [NOME]
     Cidade, 2026.  CONTRACAPA: repetir com a natureza do trabalho ("Documentação técnica da Entrega 2 do Projeto Integrador"). -->

# Entrega 2 — Hash e autenticação segura

## 1. Problema e objetivo
Uma aplicação precisa cadastrar usuários sem armazenar senhas em texto puro. Objetivo: implementar cadastro e
login com função de derivação de chave adequada (Argon2id), testar login correto e incorreto, explicar por que
SHA-256 isolado é inadequado e demonstrar comparação segura feita pela biblioteca.
Ameaças reduzidas: vazamento do banco (recuperação das senhas), ataques de dicionário/força bruta offline,
tabelas pré-computadas e enumeração de usuários.

## 2. Ambiente e tecnologias
Python 3.12, Flask 3.x, SQLite (stdlib), biblioteca `cryptography` ≥ 44 (Argon2id sobre OpenSSL), `unittest`.
Execução local em 127.0.0.1, dados fictícios, sem credenciais de terceiros.

## 3. Algoritmos/bibliotecas e justificativa
| Item | Escolha | Justificativa |
|---|---|---|
| KDF | Argon2id | Resistente a GPU/ASIC (memória) e a side-channel; listado no ASVS 11.4.2 |
| Parâmetros | m = 46 MiB, t = 2, p = 1 | Mínimo OWASP/ASVS (m ≥ 46 MiB, t = 1) com folga; ≈ 90 ms por hash no ambiente de teste |
| Salt | 16 bytes, `os.urandom`, único por usuário | Impede rainbow tables e hashes iguais para senhas iguais |
| Formato | PHC string | Guarda parâmetros + salt + hash; permite `needs_rehash` |
| Comparação | `Argon2id.verify` | Tempo constante, feita pela biblioteca (sem `==` manual) |
| Biblioteca | `cryptography` | Consolidada; não há algoritmo próprio, como exige a atividade |

**Por que SHA-256 isolado não é adequado:** é projetado para ser rápido (≈ 2,1 milhões de tentativas/s em um
núcleo; ordens de grandeza maior em GPU), não usa salt por padrão e não tem custo de memória/tempo ajustável.
Serve a integridade, não a armazenamento de senhas (slide 6 da aula).
Medido: SHA-256 ≈ 2.124.028 tentativas/s × Argon2id ≈ 11 tentativas/s (`docs/evidencias/03_*`).

## 4. Implementação e instruções de execução
Estrutura: `app/security.py` (hash, verificação, política), `app/auth.py` (cadastro/login), `app/db.py`
(SQLite parametrizado), `app/server.py` (API Flask), `tests/`, `scripts/`. Fluxo:
1. **Cadastrar:** valida usuário e senha → NFKC → Argon2id com salt novo → grava PHC string.
2. **Autenticar:** busca usuário → recalcula Argon2id com os parâmetros/salt armazenados → compara em tempo
   constante → cria sessão. Usuário inexistente usa hash isca e devolve a mesma mensagem genérica.
3. **Rehash:** se os parâmetros armazenados forem mais fracos que os atuais, o hash é regravado no login.
Instruções de execução: ver `README.md`.

## 5. Testes e evidências
20 testes automatizados, todos aprovados (`docs/evidencias/01_testes.txt`). Principais casos:
| Caso | Resultado esperado | Status |
|---|---|---|
| Login com senha correta | 200 + sessão | OK |
| Login com senha incorreta | 401 genérico, sem sessão | OK |
| Usuário inexistente | Mesma resposta da senha errada | OK |
| Banco não contém a senha | Só `$argon2id$...` | OK |
| Mesma senha, dois usuários | Hashes diferentes (salt) | OK |
| Hash adulterado / malformado | Login negado, sem exceção | OK |
| Senha curta, comum ou > 128 | Cadastro rejeitado | OK |
| Entrada `' OR '1'='1` | 401 (consulta parametrizada) | OK |
Demonstração para vídeo: `python -m scripts.demo` (`docs/evidencias/02_demo.txt`). [Anexar prints/link do vídeo.]

## 6. Riscos, limitações e melhorias
Sem rate limiting, sem TLS, sem MFA, sem checagem de senhas vazadas, logs mínimos, duplicidade de usuário
revelada no cadastro, dependências sem auditoria. Mapeamento e correções planejadas na Entrega 4
(`CONTEXTO_PROJETO.md`, seção 5). Controles atendidos: OWASP A07/A04; ASVS 11.4.2, 6.2.1, 6.2.5; ISO 27002 5.17 e 8.5.

## 7. Referências consultadas
OWASP. **Top 10:2025**. · OWASP. **Application Security Verification Standard 5.0**. · OWASP. **Password Storage
Cheat Sheet**. · ISO/IEC 27002:2022. · NIST. **Cybersecurity Framework 2.0**, 2024. · PYCA. **cryptography —
Argon2id**. · BIRYUKOV; DINU; KHOVRATOVICH. **Argon2: the memory-hard function for password hashing**, 2016 / RFC 9106.
[Completar com autor, data e data de acesso no padrão ABNT.]

## 8. Formato ABNT
Aplicar na versão final: capa, contracapa, Times/Arial 12, margens 3/2/3/2 cm, espaçamento 1,5, citações e
referências NBR 6023/10520.
