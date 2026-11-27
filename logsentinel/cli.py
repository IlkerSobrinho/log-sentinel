"""CLI: python -m logsentinel --ssh auth.log --web access.log [--json|--html out.html]"""
from __future__ import annotations

import argparse
import html
import json
import sys
from collections import Counter
from dataclasses import asdict

from . import __version__
from .detectors import Alert, detect_ssh, detect_web, sort_alerts
from .parsers import parse_ssh, parse_web

COL = {"critical": "\033[1;41m", "high": "\033[1;31m", "medium": "\033[33m", "low": "\033[36m"}
HEX = {"critical": "#dc2626", "high": "#f97316", "medium": "#eab308", "low": "#38bdf8"}


def read(path: str) -> list[str]:
    with open(path, encoding="utf-8", errors="replace") as f:
        return f.read().splitlines()


def render_text(alerts: list[Alert], color: bool) -> str:
    if not alerts:
        return "Nenhuma ameaça detectada."
    out = [f"Log Sentinel v{__version__} - {len(alerts)} alerta(s)", ""]
    for a in alerts:
        tag = f"[{a.severity.upper():8}]"
        tag = f"{COL[a.severity]}{tag}\033[0m" if color else tag
        out.append(f"{tag} {a.ip:<40} {a.rule}: {a.detail}")
    sev = Counter(a.severity for a in alerts)
    out += ["", "Resumo: " + ", ".join(f"{k}={v}" for k, v in sev.items())]
    return "\n".join(out)


def render_html(alerts: list[Alert]) -> str:
    rows = "".join(
        f"<tr><td><span style='background:{HEX[a.severity]};padding:2px 8px;border-radius:6px;color:#000'>"
        f"{a.severity}</span></td><td>{html.escape(a.ip)}</td><td>{a.rule}</td><td>{html.escape(a.detail)}</td></tr>"
        for a in alerts)
    return ("<!doctype html><meta charset=utf-8><title>Log Sentinel</title>"
            "<style>body{font:14px system-ui;background:#0b1220;color:#e2e8f0;padding:30px}"
            "table{border-collapse:collapse;width:100%}td,th{padding:10px;border-bottom:1px solid #1e293b;text-align:left}"
            "h1{background:linear-gradient(90deg,#a5b4fc,#22d3ee);-webkit-background-clip:text;color:transparent}</style>"
            f"<h1>🛡️ Log Sentinel</h1><p>{len(alerts)} alerta(s)</p>"
            f"<table><tr><th>Severidade</th><th>IP</th><th>Regra</th><th>Detalhe</th></tr>{rows}</table>")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="logsentinel", description="Detecta ataques em logs SSH e web.")
    p.add_argument("--ssh", help="arquivo auth.log / secure")
    p.add_argument("--web", help="access.log (nginx/apache combined)")
    p.add_argument("--year", type=int, help="ano dos logs SSH (padrão: atual)")
    p.add_argument("--threshold", type=int, default=5, help="falhas SSH na janela")
    p.add_argument("--json", action="store_true")
    p.add_argument("--html", metavar="ARQUIVO")
    a = p.parse_args(argv)
    if not (a.ssh or a.web):
        p.error("informe --ssh e/ou --web")
    alerts: list[Alert] = []
    if a.ssh:
        alerts += detect_ssh(list(parse_ssh(read(a.ssh), a.year)), a.threshold)
    if a.web:
        alerts += detect_web(list(parse_web(read(a.web))))
    alerts = sort_alerts(alerts)
    if a.html:
        open(a.html, "w", encoding="utf-8").write(render_html(alerts))
    print(json.dumps([asdict(x) for x in alerts], indent=2, ensure_ascii=False) if a.json
          else render_text(alerts, sys.stdout.isatty()))
    return 2 if any(x.severity in ("critical", "high") for x in alerts) else 0


if __name__ == "__main__":
    sys.exit(main())
