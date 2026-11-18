# Projeto Integrador — Segurança Aplicada ao Desenvolvimento
**Entrega 2 — Hash e autenticação segura** (cadastro/login sem senha em texto puro)

Contexto completo e plano das Entregas 3 e 4: [`CONTEXTO_PROJETO.md`](CONTEXTO_PROJETO.md)

## Execução
```bash
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python -m unittest discover -v                          # 20 testes
python -m scripts.demo                                  # demonstração (usar no vídeo)
python -m scripts.benchmark_sha256_vs_argon2            # SHA-256 x Argon2id
cp .env.example .env  &&  export SECRET_KEY=$(python -c "import secrets;print(secrets.token_hex(32))")
python -m app.server                                    # API em http://127.0.0.1:5000
```
Exemplo com curl:
```bash
curl -s -X POST localhost:5000/register -H 'Content-Type: application/json' -d '{"username":"maria","password":"correta-cavalo-bateria"}'
curl -s -c c.txt -X POST localhost:5000/login -H 'Content-Type: application/json' -d '{"username":"maria","password":"correta-cavalo-bateria"}'
curl -s -b c.txt localhost:5000/me
```

## Decisões técnicas
- **Argon2id** (`cryptography`/OpenSSL): m = 46 MiB, t = 2, p = 1, salt aleatório de 16 B por usuário (ASVS 11.4.2).
- Armazena **PHC string** (parâmetros + salt + hash) → permite `needs_rehash` e migração futura.
- Comparação segura feita pela biblioteca (`Argon2id.verify`, tempo constante).
- Política: ≥ 8 caracteres (15 recomendado), ≤ 128, sem regras de composição (ASVS 6.2.1 e 6.2.5).
- Login com mensagem genérica e hash isca contra enumeração de usuários.

## Por que SHA-256 isolado não serve para senhas
É rápido por projeto (≈ 2 milhões de tentativas/s em 1 núcleo na nossa medição; GPUs fazem bilhões),
não tem salt (mesma senha → mesmo hash → rainbow tables e identificação de senhas repetidas) e não
tem custo de memória configurável. Argon2id é deliberadamente lento e exige memória: ≈ 11 tentativas/s
no mesmo núcleo (`docs/evidencias/03_*.txt`).

## Limites da solução
Ver tabela L1–L7 em `CONTEXTO_PROJETO.md` (sem rate limiting, sem TLS, sem MFA etc.). São intencionais
para a Entrega 4: serão auditadas, corrigidas e retestadas.
