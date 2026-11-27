"""Parsers de logs: SSH (auth.log/syslog) e Nginx/Apache (formato combined)."""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Iterable, Iterator

MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}

SSH_RE = re.compile(r"^(?P<mon>\w{3})\s+(?P<day>\d+)\s+(?P<time>[\d:]{8})\s+\S+\s+sshd\[\d+\]:\s+(?P<msg>.*)$")
FAILED_RE = re.compile(r"Failed (?P<method>\w+(?:-\w+)?) for (?P<invalid>invalid user )?(?P<user>\S+) from (?P<ip>[\da-fA-F.:]+)")
INVALID_RE = re.compile(r"Invalid user (?P<user>\S*) from (?P<ip>[\da-fA-F.:]+)")
ACCEPTED_RE = re.compile(r"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>[\da-fA-F.:]+)")

WEB_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+)[^"]*" '
    r'(?P<status>\d{3}) (?P<size>\S+)(?: "(?P<ref>[^"]*)" "(?P<ua>[^"]*)")?')


@dataclass
class SshEvent:
    ts: datetime
    kind: str          # failed | invalid | accepted
    user: str
    ip: str
    method: str = ""


@dataclass
class WebEvent:
    ts: datetime
    ip: str
    method: str
    path: str
    status: int
    ua: str = ""


def parse_ssh(lines: Iterable[str], year: int | None = None) -> Iterator[SshEvent]:
    year = year or datetime.now().year
    for line in lines:
        m = SSH_RE.match(line.strip())
        if not m:
            continue
        try:
            ts = datetime.strptime(f"{year} {MONTHS[m['mon']]} {m['day']} {m['time']}", "%Y %m %d %H:%M:%S")
        except (KeyError, ValueError):
            continue
        msg = m["msg"]
        if (f := FAILED_RE.search(msg)):
            yield SshEvent(ts, "failed", f["user"], f["ip"], f["method"])
        elif (i := INVALID_RE.search(msg)):
            yield SshEvent(ts, "invalid", i["user"], i["ip"])
        elif (a := ACCEPTED_RE.search(msg)):
            yield SshEvent(ts, "accepted", a["user"], a["ip"], a["method"])


def parse_web(lines: Iterable[str]) -> Iterator[WebEvent]:
    for line in lines:
        m = WEB_RE.match(line.strip())
        if not m:
            continue
        try:
            ts = datetime.strptime(m["ts"].split()[0], "%d/%b/%Y:%H:%M:%S")
        except ValueError:
            continue
        yield WebEvent(ts, m["ip"], m["method"], m["path"], int(m["status"]), m["ua"] or "")
