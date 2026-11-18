# Tabela de exposição (Entrega 3)
Comando executado: `nmap ...` · Escopo: ... · Data: ...

| Porta | Protocolo | Serviço/versão | Necessário? | Risco | Recomendação |
|---|---|---|---|---|---|
| 22 | TCP | OpenSSH x.y | Sim (admin) | Força bruta de senha | Chaves, PasswordAuthentication no, restringir origem |
| 5000 | TCP | Flask/Werkzeug (app) | Sim | HTTP sem TLS | Proxy reverso com TLS, servidor WSGI de produção |
