# 🛡️ Log Sentinel

Analisador de logs **SSH** e **Nginx/Apache** que detecta ataques comuns. Python puro, sem dependências.

## O que detecta
| Regra | Severidade | Descrição |
|---|---|---|
| `ssh_success_after_bruteforce` | crítica | Login aceito logo após força bruta (possível comprometimento) |
| `ssh_bruteforce` | alta | N falhas na janela deslizante (padrão 5 em 5 min) |
| `ssh_user_enumeration` | média | Muitos usuários distintos testados pelo mesmo IP |
| `ssh_root_login` | média | Login direto como root |
| `web_malicious_payload` | alta | `.env`, `../`, SQLi, XSS, `wp-login`, `phpmyadmin`... |
| `web_login_bruteforce` | alta | Rajada de POSTs em rotas de login |
| `web_scan` | média | Rajada de 401/403/404 (varredura de diretórios) |
| `web_scanner_ua` | baixa | User-Agent de sqlmap, nikto, nmap, hydra... |

## Uso
```bash
python -m logsentinel --ssh samples/auth.log --web samples/access.log
python -m logsentinel --ssh /var/log/auth.log --json
python -m logsentinel --web access.log --html relatorio.html
pytest
```
Código de saída `2` quando há alertas críticos/altos (útil em cron/CI).

## Estrutura
`parsers.py` (regex dos formatos) · `detectors.py` (regras com janela deslizante) · `cli.py` (texto/JSON/HTML)

## Roadmap
- [ ] Bloqueio automático via `ufw`/`iptables` (modo `--block`)
- [ ] Geolocalização de IPs · alertas por Telegram
- [ ] Modo `--follow` (tempo real)

Feito por **Ilker Sobrinho** como estudo de detecção de intrusão.
