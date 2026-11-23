"""Build outgoing messages, including correctly threaded replies to an original email."""
from __future__ import annotations

import re
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import formataddr, formatdate, getaddresses, make_msgid


def _domain(addr: str) -> str:
    return addr.rsplit("@", 1)[-1] if "@" in addr else "localhost"


def build_message(from_addr: str, from_name: str, to: list[str], subject: str, body: str,
                  cc: list[str] | None = None, html: str | None = None,
                  in_reply_to: str | None = None, references: str | None = None) -> EmailMessage:
    msg = EmailMessage()
    msg["From"] = formataddr((from_name, from_addr)) if from_name else from_addr
    msg["To"] = ", ".join(to)
    if cc:
        msg["Cc"] = ", ".join(cc)
    msg["Subject"] = subject
    msg["Date"] = formatdate(localtime=False, usegmt=True)
    msg["Message-ID"] = make_msgid(domain=_domain(from_addr))
    if in_reply_to:
        msg["In-Reply-To"] = in_reply_to
        msg["References"] = (references + " " + in_reply_to).strip() if references else in_reply_to
    msg.set_content(body)
    if html:
        msg.add_alternative(html, subtype="html")
    return msg


def parse_original(raw: bytes) -> EmailMessage:
    return BytesParser(policy=policy.default).parsebytes(raw)


def _reply_subject(subject: str) -> str:
    subject = subject or ""
    return subject if re.match(r"^\s*re\s*:", subject, re.I) else f"Re: {subject}".strip()


def _quote(original: EmailMessage) -> str:
    part = original.get_body(preferencelist=("plain",))
    text = part.get_content() if part else ""
    sender = original.get("From", "")
    date = original.get("Date", "")
    quoted = "\n".join("> " + line for line in text.strip().splitlines())
    return f"\n\nOn {date}, {sender} wrote:\n{quoted}\n"


def build_reply(original: EmailMessage, from_addr: str, from_name: str, body: str,
                reply_all: bool = False, quote: bool = True, html: str | None = None) -> EmailMessage:
    """Reply to Reply-To (or From), keep the thread with In-Reply-To / References."""
    target = original.get("Reply-To") or original.get("From")
    to = [a for _, a in getaddresses([target]) if a]
    cc: list[str] = []
    if reply_all:
        me = from_addr.lower()
        others = getaddresses(original.get_all("To", []) + original.get_all("Cc", []))
        cc = [a for _, a in others if a and a.lower() != me and a not in to]
    if not to:
        raise ValueError("original message has no From or Reply-To address")
    text = body + (_quote(original) if quote else "")
    return build_message(
        from_addr, from_name, to, _reply_subject(original.get("Subject", "")), text,
        cc=cc or None, html=html,
        in_reply_to=original.get("Message-ID"),
        references=original.get("References"),
    )
