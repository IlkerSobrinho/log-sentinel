"""Detectores: força bruta SSH, enumeração de usuários, varredura web e payloads suspeitos."""
from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import timedelta

from .parsers import SshEvent, WebEvent

SUSPICIOUS_PATHS = re.compile(
    r"(\.env|\.git/|wp-login|wp-admin|xmlrpc\.php|phpmyadmin|/etc/passwd|\.\./|cmd\.exe|"
    r"/bin/sh|union(\+|%20| )select|<script|%3cscript|boaform|actuator|\.aws/|id_rsa)", re.I)
BAD_UA = re.compile(r"(sqlmap|nikto|nmap|masscan|zgrab|gobuster|dirbuster|hydra|wpscan|curl/|python-requests)", re.I)


@dataclass
class Alert:
    severity: str      # critical | high | medium | low
    rule: str
    ip: str
    detail: str
    count: int = 1
    extra: dict = field(default_factory=dict)


def _burst(times, window: timedelta, threshold: int) -> int:
    """Maior nº de eventos dentro de uma janela deslizante."""
    times = sorted(times)
    best, j = 0, 0
    for i, t in enumerate(times):
        while t - times[j] > window:
            j += 1
        best = max(best, i - j + 1)
    return best if best >= threshold else 0


def detect_ssh(events: list[SshEvent], threshold: int = 5, window_min: int = 5) -> list[Alert]:
    alerts: list[Alert] = []
    fails: dict[str, list] = defaultdict(list)
    users: dict[str, set] = defaultdict(set)
    ok: dict[str, list[SshEvent]] = defaultdict(list)
    for e in events:
        if e.kind in ("failed", "invalid"):
            fails[e.ip].append(e.ts)
            users[e.ip].add(e.user)
        elif e.kind == "accepted":
            ok[e.ip].append(e)
    win = timedelta(minutes=window_min)
    for ip, ts in fails.items():
        n = _burst(ts, win, threshold)
        if n:
            alerts.append(Alert("high", "ssh_bruteforce", ip,
                                f"{n} falhas em {window_min} min ({len(ts)} no total)", len(ts)))
            if ip in ok:  # sucesso depois de força bruta = possível comprometimento
                last = ok[ip][-1]
                alerts.append(Alert("critical", "ssh_success_after_bruteforce", ip,
                                    f"Login aceito para '{last.user}' após tentativas de força bruta", 1))
        if len(users[ip]) >= 4:
            alerts.append(Alert("medium", "ssh_user_enumeration", ip,
                                f"{len(users[ip])} usuários distintos testados: "
                                + ", ".join(sorted(users[ip])[:6]), len(users[ip])))
    for ip, evs in ok.items():
        if any(e.user == "root" for e in evs):
            alerts.append(Alert("medium", "ssh_root_login", ip, "Login direto como root aceito"))
    return alerts


def detect_web(events: list[WebEvent], scan_threshold: int = 15, window_min: int = 2) -> list[Alert]:
    alerts: list[Alert] = []
    by_ip: dict[str, list[WebEvent]] = defaultdict(list)
    for e in events:
        by_ip[e.ip].append(e)
    win = timedelta(minutes=window_min)
    for ip, evs in by_ip.items():
        errs = [e.ts for e in evs if e.status in (401, 403, 404)]
        n = _burst(errs, win, scan_threshold)
        if n:
            alerts.append(Alert("medium", "web_scan", ip, f"{n} respostas 401/403/404 em {window_min} min"
                                " (varredura de diretórios)", len(errs)))
        bad = [e for e in evs if SUSPICIOUS_PATHS.search(e.path)]
        if bad:
            alerts.append(Alert("high", "web_malicious_payload", ip,
                                f"{len(bad)} requisições suspeitas, ex.: {bad[0].path[:80]}", len(bad)))
        uas = {e.ua for e in evs if BAD_UA.search(e.ua)}
        if uas:
            alerts.append(Alert("low", "web_scanner_ua", ip, "User-Agent de ferramenta: " + ", ".join(sorted(uas))[:80]))
        logins = [e.ts for e in evs if e.method == "POST" and re.search(r"login|signin|auth", e.path, re.I)]
        n = _burst(logins, win, 10)
        if n:
            alerts.append(Alert("high", "web_login_bruteforce", ip, f"{n} POSTs de login em {window_min} min", n))
    return alerts


ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def sort_alerts(alerts: list[Alert]) -> list[Alert]:
    return sorted(alerts, key=lambda a: (ORDER[a.severity], -a.count))
