# Contexto do Projeto Integrador — Segurança Aplicada ao Desenvolvimento

> Arquivo-mestre reutilizável. Cole/anexe este arquivo ao iniciar a Entrega 3 e a Entrega 4
> (em uma conversa com a IA ou para o seu grupo) para manter tudo consistente.

## 1. Disciplina e regras
- Curso: Sistemas de Informação/ADS · Disciplina: Segurança da Informação · UNIT
- Docente: Profa. Ma. Ana Carla do Nascimento Santos · Atividade avaliativa: 8,0 pontos
- Data final de entrega indicada no PDF: **02/12/2026** · 4 entregas semanais progressivas
- Individual ou até 3 estudantes · linguagem/framework livres
- Cada entrega: repositório/código + README + evidências (vídeo vale) + documentação técnica
- **Testes só em ambientes próprios ou autorizados.** Sem dados reais ou credenciais de terceiros.
- **Proibido** criar algoritmo criptográfico próprio: usar bibliotecas consolidadas.
- Pesos: implementação/requisitos 40% · testes/evidências/reprodutibilidade 25% ·
  justificativa técnica/riscos 20% · organização/documentação 15%

## 2. Modelo de documentação (repetir em TODAS as entregas)
1. Problema e objetivo · 2. Ambiente e tecnologias · 3. Algoritmos/bibliotecas e justificativa ·
4. Implementação e instruções de execução · 5. Testes e evidências · 6. Riscos, limitações e melhorias ·
7. Referências · 8. Formato ABNT, com capa e contracapa

## 3. Estratégia: UM sistema, quatro entregas
O mesmo projeto evolui; a aplicação da Entrega 2 vira o **alvo** das Entregas 3 e 4.

| Entrega | Foco | Papel da aplicação (`app/`) |
|---|---|---|
| 1 | Criptografia assimétrica / PKI | Pode virar um módulo `app/crypto_msg.py` (AES-GCM + RSA-OAEP ou Ed25519) |
| **2** | Hash e autenticação (**feita**) | Cadastro/login com Argon2id |
| 3 | Nmap, portas e serviços | É o serviço exposto no laboratório (porta 5000/TCP) |
| 4 | Auditoria e correção | É o sistema auditado; as limitações da seção 5 viram achados |

## 4. Estado atual (Entrega 2)
- Stack: Python 3.12 + Flask + SQLite + `cryptography` (Argon2id via OpenSSL)
- Argon2id: m = 47104 KiB (46 MiB), t = 2, p = 1, salt 16 B aleatório, hash 32 B (PHC string)
- Endpoints: `POST /register`, `POST /login`, `GET /me`, `POST /logout` (escuta em 127.0.0.1:5000)
- Controles já presentes: política ASVS 6.2.1/6.2.5, normalização NFKC, salt único, comparação em tempo
  constante, mensagem de login genérica, hash isca (anti-enumeração), consultas parametrizadas,
  erro genérico sem stack trace, segredo via variável de ambiente, cookie HttpOnly + SameSite=Lax
- 20 testes automatizados (`python -m unittest discover -v`) — todos passam
- Comandos: ver `README.md`

## 5. Limitações conhecidas (candidatas a achados na Entrega 4)
| ID | Limitação | OWASP Top 10:2025 | ASVS 5.0 | ISO 27002:2022 | Correção sugerida |
|---|---|---|---|---|---|
| L1 | Sem limite de tentativas / bloqueio de força bruta | A07 | V6 (autenticação) | 8.5 | Rate limiting + atraso progressivo |
| L2 | HTTP sem TLS | A04 / A02 | 12.1.1 | 8.24 | Proxy reverso com TLS 1.2/1.3 |
| L3 | Sem cabeçalhos de segurança (CSP, X-Content-Type-Options…) | A02 | V13 | 8.9 | Cabeçalhos no Flask/proxy |
| L4 | Blocklist mínima, sem checagem de senhas vazadas | A07 | 6.2.12 | 5.17 | Lista de vazadas (ex.: k-anonymity) |
| L5 | Sem MFA e sem log de eventos de autenticação | A09 / A07 | V16 | 8.15 | Logar falhas/sucessos sem dados sensíveis |
| L6 | Dependências sem auditoria automática | A03 | 15.2.1 | 8.8 | `pip-audit` + versões fixadas |
| L7 | Cadastro revela usuário duplicado (409) | A07 | V6 | 8.5 | Fluxo com confirmação por e-mail |

## 6. Plano da Entrega 3 (Nmap) — como reutilizar
- Laboratório: VM Linux (ou WSL/Docker) própria, rodando a aplicação em `HOST=0.0.0.0 PORT=5000`
  só dentro da rede do lab, e opcionalmente `sshd` para analisar autenticação remota
- Registrar **autorização e escopo** (modelo em `docs/modelos/autorizacao_escopo.md`)
- Comandos típicos (só no escopo!): `nmap -sn <rede>` · `nmap -sS -sV -p- <ip-lab>` · `nmap -sV -sC -p 22,5000 <ip-lab>`
- Entregar a tabela porta/protocolo/serviço/risco/recomendação (modelo em `docs/modelos/tabela_portas.md`)
- SSH: desativar senha (`PasswordAuthentication no`), preferir chaves, `PermitRootLogin no`, limitar usuários/origem
- Referências: OWASP A02, ASVS V13 e 12.1.1, ISO 27002 8.20/8.21/8.8

## 7. Plano da Entrega 4 (auditoria) — como reutilizar
1. Escolher ≥ 2 achados verificáveis da seção 5 (sugestão: L1 rate limiting e L3 cabeçalhos, ou L6)
2. Evidência "antes" (ex.: 20 logins errados seguidos sem bloqueio; `curl -I` sem cabeçalhos)
3. Corrigir no código · 4. Reteste com evidência "depois" · 5. Preencher `docs/modelos/matriz_achados.md`
6. Cada achado cita: categoria Top 10 + requisito ASVS + controle ISO (ou função NIST CSF)

## 8. Pasta de evidências
`docs/evidencias/` guarda saídas de testes, prints e logs (nomear `NN_descricao.ext`).
