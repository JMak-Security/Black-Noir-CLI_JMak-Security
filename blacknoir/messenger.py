"""Messaging providers — read own inbox + bounded, human-triggered single send.

Every provider obeys the same rules:
  * READ is text-only. Bodies are run through `sanitize_message_content` — links
    and attachments are inert text, never fetched or opened ("no virus").
  * SEND is one message per call, gated by `confirm_cb(preview) -> bool`. There
    is deliberately NO bulk/loop/schedule API. A human confirms every send.

Providers:
  * EmailProvider   — IMAP read + SMTP send (stdlib; Gmail App Password).
  * TelegramProvider— send via Telethon if available (reads use Telepathy).
  * MetaProvider    — Instagram / Facebook Page / Threads via Meta Graph API
                      (own inbox + reply-in-window; needs a Meta app token).

Only official platform APIs are used. No account creation, no automation, no
cold-DM, no reading other users' private content.
"""

from __future__ import annotations

import email as _email
import imaplib
import os
import smtplib
from email.header import decode_header, make_header
from email.mime.text import MIMEText
from typing import Callable

from .guardrails import sanitize_message_content
from .models import InboxItem, SendResult

ConfirmCb = Callable[[str], bool]


def _env(*names: str, default: str = "") -> str:
    for n in names:
        v = os.environ.get(n)
        if v:
            return v
    return default


# --- base -------------------------------------------------------------------

class MessengerProvider:
    name = "base"

    def available(self) -> tuple[bool, str]:
        return False, "not configured"

    def list_inbox(self, limit: int = 15) -> list[InboxItem]:
        return []

    def send(self, recipient: str, text: str, confirm_cb: ConfirmCb) -> SendResult:
        return SendResult(False, self.name, recipient, "send not supported")

    def read_comments(self, target: str, limit: int = 15) -> list[InboxItem]:
        return []

    def comment(self, target: str, text: str, confirm_cb: ConfirmCb) -> SendResult:
        return SendResult(False, self.name, target, "comment not supported")


# --- Email (IMAP + SMTP) ----------------------------------------------------

class EmailProvider(MessengerProvider):
    name = "email"

    def __init__(self) -> None:
        self.address = _env("EMAIL_ADDRESS", "GMAIL_ADDRESS")
        self.password = _env("EMAIL_APP_PASSWORD", "GMAIL_APP_PASSWORD")
        self.imap_host = _env("IMAP_HOST", default="imap.gmail.com")
        self.imap_port = int(_env("IMAP_PORT", default="993"))
        self.smtp_host = _env("SMTP_HOST", default="smtp.gmail.com")
        self.smtp_port = int(_env("SMTP_PORT", default="587"))

    def available(self) -> tuple[bool, str]:
        if self.address and self.password:
            return True, "ok"
        return False, "set EMAIL_ADDRESS + EMAIL_APP_PASSWORD (Gmail App Password)"

    @staticmethod
    def _dh(value: str) -> str:
        try:
            return str(make_header(decode_header(value)))
        except Exception:
            return value or ""

    def list_inbox(self, limit: int = 15) -> list[InboxItem]:
        ok, _ = self.available()
        if not ok:
            return []
        items: list[InboxItem] = []
        try:
            M = imaplib.IMAP4_SSL(self.imap_host, self.imap_port)
            M.login(self.address, self.password)
            M.select("INBOX")
            typ, data = M.search(None, "ALL")
            ids = data[0].split()[-limit:] if data and data[0] else []
            for mid in reversed(ids):
                typ, md = M.fetch(mid, "(RFC822)")
                if typ != "OK" or not md or not md[0]:
                    continue
                msg = _email.message_from_bytes(md[0][1])
                items.append(self._parse(msg))
            M.logout()
        except Exception as exc:
            return [InboxItem("email", subject=f"(email read error: "
                              f"{type(exc).__name__})")]
        return items

    def _parse(self, msg) -> InboxItem:
        sender = self._dh(msg.get("From", ""))
        subject = self._dh(msg.get("Subject", ""))
        date = msg.get("Date", "")
        body, is_html = "", False
        attachments: list[str] = []
        if msg.is_multipart():
            for part in msg.walk():
                disp = str(part.get("Content-Disposition") or "")
                ctype = part.get_content_type()
                if "attachment" in disp.lower():
                    fn = self._dh(part.get_filename() or "attachment")
                    attachments.append(fn)          # name only — never opened
                    continue
                if ctype == "text/plain" and not body:
                    body = self._decode(part); is_html = False
                elif ctype == "text/html" and not body:
                    body = self._decode(part); is_html = True
        else:
            body = self._decode(msg)
            is_html = msg.get_content_type() == "text/html"
        clean = sanitize_message_content(body, is_html=is_html)
        return InboxItem("email", sender=sender, subject=subject, date=date,
                         body=clean["text"][:4000], links=clean["links"],
                         attachments=attachments,
                         meta={"images_blocked": clean["images"]})

    @staticmethod
    def _decode(part) -> str:
        try:
            payload = part.get_payload(decode=True)
            if payload is None:
                return ""
            charset = part.get_content_charset() or "utf-8"
            return payload.decode(charset, errors="replace")
        except Exception:
            return ""

    def send(self, recipient: str, text: str, confirm_cb: ConfirmCb) -> SendResult:
        ok, reason = self.available()
        if not ok:
            return SendResult(False, self.name, recipient, reason)
        subject = (text.strip().splitlines() or ["(no subject)"])[0][:60]
        preview = (f"[EMAIL]\nFrom: {self.address}\nTo: {recipient}\n"
                   f"Subject: {subject}\n\n{text}")
        if not confirm_cb(preview):
            return SendResult(False, self.name, recipient, "not confirmed",
                              preview=preview)
        try:
            m = MIMEText(text, "plain", "utf-8")
            m["From"], m["To"], m["Subject"] = self.address, recipient, subject
            s = smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=30)
            s.starttls(); s.login(self.address, self.password)
            s.sendmail(self.address, [recipient], m.as_string())
            s.quit()
            return SendResult(True, self.name, recipient, "sent 1 email",
                              preview=preview)
        except Exception as exc:
            return SendResult(False, self.name, recipient,
                              f"{type(exc).__name__}: {exc}", preview=preview)


# --- Telegram (send via Telethon if available) ------------------------------

class TelegramProvider(MessengerProvider):
    name = "telegram"

    def __init__(self) -> None:
        self.session = _env("TELEGRAM_SESSION", default="")
        self.api_id = _env("TELEGRAM_API_ID", default="")
        self.api_hash = _env("TELEGRAM_API_HASH", default="")

    def available(self) -> tuple[bool, str]:
        try:
            import telethon  # noqa: F401
        except Exception:
            return False, "telethon not installed in this environment"
        if self.session and self.api_id and self.api_hash:
            return True, "ok"
        return False, "set TELEGRAM_SESSION + TELEGRAM_API_ID + TELEGRAM_API_HASH"

    def send(self, recipient: str, text: str, confirm_cb: ConfirmCb) -> SendResult:
        ok, reason = self.available()
        if not ok:
            return SendResult(False, self.name, recipient, reason)
        preview = f"[TELEGRAM]\nTo: {recipient}\n\n{text}"
        if not confirm_cb(preview):
            return SendResult(False, self.name, recipient, "not confirmed",
                              preview=preview)
        try:
            from telethon.sync import TelegramClient
            with TelegramClient(self.session, int(self.api_id),
                                self.api_hash) as client:
                client.send_message(recipient, text)     # one message only
            return SendResult(True, self.name, recipient, "sent 1 message",
                              preview=preview)
        except Exception as exc:
            return SendResult(False, self.name, recipient,
                              f"{type(exc).__name__}: {exc}", preview=preview)


# --- Meta (Instagram / Facebook Page / Threads) -----------------------------

class MetaProvider(MessengerProvider):
    """Own-inbox only, via the Meta Graph API. Needs a Meta app access token
    + App-Reviewed messaging permission. Cannot read targets or cold-DM."""
    GRAPH = "https://graph.facebook.com/v21.0"

    def __init__(self, platform: str) -> None:
        self.platform = platform          # instagram | facebook | threads
        self.name = platform
        if platform == "threads":
            self.token = _env("THREADS_ACCESS_TOKEN") or _env("META_ACCESS_TOKEN")
            self.obj_id = _env("THREADS_USER_ID")
            self.base = "https://graph.threads.net/v1.0"
        elif platform == "instagram" and _env("IG_ACCESS_TOKEN"):
            # Instagram API with Instagram Login (no FB Page needed)
            self.token = _env("IG_ACCESS_TOKEN")
            self.obj_id = _env("IG_USER_ID")
            self.base = "https://graph.instagram.com/v21.0"
        else:
            self.token = _env("META_ACCESS_TOKEN")
            self.obj_id = _env({"instagram": "IG_BUSINESS_ID",
                                "facebook": "FB_PAGE_ID"}.get(platform, ""))
            self.base = self.GRAPH

    def available(self) -> tuple[bool, str]:
        if self.token and self.obj_id:
            return True, "ok"
        if self.platform == "threads":
            return False, "needs THREADS_ACCESS_TOKEN + THREADS_USER_ID"
        if self.platform == "instagram":
            return False, ("needs IG_ACCESS_TOKEN + IG_USER_ID (Instagram Login) "
                           "or META_ACCESS_TOKEN + IG_BUSINESS_ID")
        return False, ("needs META_ACCESS_TOKEN + the account id "
                       "(FB_PAGE_ID) and messaging permission")

    def _is_ig_login(self) -> bool:
        return self.base.startswith("https://graph.instagram.com")

    def list_inbox(self, limit: int = 15) -> list[InboxItem]:
        ok, _ = self.available()
        if not ok:
            return []
        if self._is_ig_login():
            return self._ig_login_inbox(limit)
        try:
            import requests
            r = requests.get(
                f"{self.base}/{self.obj_id}/conversations",
                params={"platform": self.platform, "access_token": self.token,
                        "fields": "messages{message,from,created_time}",
                        "limit": limit}, timeout=30)
            data = r.json() if r.status_code < 400 else {}
        except Exception as exc:
            return [InboxItem(self.platform,
                              subject=f"(meta read error: {type(exc).__name__})")]
        items: list[InboxItem] = []
        for conv in (data.get("data") or []):
            for m in (conv.get("messages", {}).get("data") or [])[:limit]:
                clean = sanitize_message_content(m.get("message", ""))
                items.append(InboxItem(
                    self.platform,
                    sender=str((m.get("from") or {}).get("username", "")),
                    date=m.get("created_time", ""),
                    body=clean["text"][:2000], links=clean["links"]))
        return items

    def _ig_login_inbox(self, limit: int) -> list[InboxItem]:
        """Instagram Login: read comments on your own recent media."""
        try:
            import requests
            media = requests.get(
                f"{self.base}/me/media",
                params={"fields": "id,caption,comments_count,permalink",
                        "access_token": self.token, "limit": limit}, timeout=30
            ).json().get("data", [])
            items = []
            for m in media:
                if not m.get("comments_count"):
                    continue
                cs = requests.get(
                    f"{self.base}/{m['id']}/comments",
                    params={"fields": "text,username,timestamp",
                            "access_token": self.token}, timeout=30
                ).json().get("data", [])
                for c in cs:
                    clean = sanitize_message_content(c.get("text", ""))
                    items.append(InboxItem(
                        "instagram", sender=c.get("username", ""),
                        subject=f"comment on {m.get('permalink', '')[:40]}",
                        date=c.get("timestamp", ""), body=clean["text"][:1000],
                        links=clean["links"], meta={"comment_id": c.get("id")}))
            return items[:limit]
        except Exception as exc:
            return [InboxItem("instagram",
                              subject=f"(ig read error: {type(exc).__name__})")]

    def send(self, recipient: str, text: str, confirm_cb: ConfirmCb) -> SendResult:
        ok, reason = self.available()
        if not ok:
            return SendResult(False, self.name, recipient, reason)
        preview = (f"[{self.platform.upper()}] reply (within messaging window)\n"
                   f"To: {recipient}\n\n{text}")
        if not confirm_cb(preview):
            return SendResult(False, self.name, recipient, "not confirmed",
                              preview=preview)
        try:
            import requests
            r = requests.post(
                f"{self.base}/{self.obj_id}/messages",
                json={"recipient": {"id": recipient},
                      "message": {"text": text}},
                params={"access_token": self.token}, timeout=30)
            if r.status_code < 400:
                return SendResult(True, self.name, recipient, "sent 1 reply",
                                  preview=preview)
            return SendResult(False, self.name, recipient,
                              f"api {r.status_code}: {r.text[:150]}",
                              preview=preview)
        except Exception as exc:
            return SendResult(False, self.name, recipient,
                              f"{type(exc).__name__}: {exc}", preview=preview)

    def comment(self, target: str, text: str, confirm_cb: ConfirmCb) -> SendResult:
        """IG/FB: reply on your OWN post/comment (target = media/comment id).
        Threads: reply to a public thread (target = thread id)."""
        ok, reason = self.available()
        if not ok:
            return SendResult(False, self.name, target, reason)
        scope = ("public thread reply" if self.platform == "threads"
                 else "reply on your own post")
        preview = f"[{self.platform.upper()}] {scope}\nOn: {target}\n\n{text}"
        if not confirm_cb(preview):
            return SendResult(False, self.name, target, "not confirmed",
                              preview=preview)
        try:
            import requests
            if self.platform == "threads":
                base = "https://graph.threads.net/v1.0"
                tok = _env("THREADS_ACCESS_TOKEN") or self.token
                c = requests.post(f"{base}/{self.obj_id}/threads", params={
                    "media_type": "TEXT", "text": text, "reply_to_id": target,
                    "access_token": tok}, timeout=30)
                cid = (c.json() or {}).get("id") if c.status_code < 400 else None
                if not cid:
                    return SendResult(False, self.name, target,
                                      f"threads create {c.status_code}: "
                                      f"{c.text[:120]}", preview=preview)
                p = requests.post(f"{base}/{self.obj_id}/threads_publish",
                                  params={"creation_id": cid, "access_token": tok},
                                  timeout=30)
                ok2 = p.status_code < 400
                return SendResult(ok2, self.name, target,
                                  "posted 1 reply" if ok2
                                  else f"publish {p.status_code}: {p.text[:120]}",
                                  preview=preview)
            # instagram / facebook — comment on own object
            r = requests.post(f"{self.base}/{target}/comments",
                              params={"message": text, "access_token": self.token},
                              timeout=30)
            ok2 = r.status_code < 400
            return SendResult(ok2, self.name, target,
                              "posted 1 comment" if ok2
                              else f"api {r.status_code}: {r.text[:120]}",
                              preview=preview)
        except Exception as exc:
            return SendResult(False, self.name, target,
                              f"{type(exc).__name__}: {exc}", preview=preview)


# --- YouTube (comment on ANY video) -----------------------------------------

import re as _re


def _yt_video_id(s: str) -> str:
    s = s.strip()
    m = _re.search(r"(?:v=|/shorts/|youtu\.be/|/watch\?.*v=)([A-Za-z0-9_-]{11})", s)
    if m:
        return m.group(1)
    return s if _re.fullmatch(r"[A-Za-z0-9_-]{11}", s) else s


class YouTubeProvider(MessengerProvider):
    """Read a video's public comments (API key) + post ONE comment (OAuth).

    Reading needs YOUTUBE_API_KEY. Posting a comment needs an OAuth2 access
    token (YOUTUBE_OAUTH_TOKEN, scope youtube.force-ssl) — an API key alone
    cannot write."""
    name = "youtube"
    BASE = "https://www.googleapis.com/youtube/v3"

    def __init__(self) -> None:
        self.api_key = _env("YOUTUBE_API_KEY")
        self.oauth = _env("YOUTUBE_OAUTH_TOKEN")

    def available(self) -> tuple[bool, str]:
        if self.api_key or self.oauth:
            return True, "ok"
        return False, "set YOUTUBE_API_KEY (read) and/or YOUTUBE_OAUTH_TOKEN (post)"

    def read_comments(self, target: str, limit: int = 15) -> list[InboxItem]:
        if not self.api_key:
            return []
        vid = _yt_video_id(target)
        try:
            import requests
            r = requests.get(f"{self.BASE}/commentThreads", params={
                "part": "snippet", "videoId": vid, "maxResults": min(limit, 50),
                "key": self.api_key, "textFormat": "plainText"}, timeout=30)
            data = r.json() if r.status_code < 400 else {}
        except Exception as exc:
            return [InboxItem("youtube",
                              subject=f"(youtube read error: {type(exc).__name__})")]
        items = []
        for it in (data.get("items") or []):
            sn = it.get("snippet", {}).get("topLevelComment", {}).get("snippet", {})
            clean = sanitize_message_content(sn.get("textDisplay", ""))
            items.append(InboxItem(
                "youtube", sender=sn.get("authorDisplayName", ""),
                subject=f"comment on {vid}", date=sn.get("publishedAt", ""),
                body=clean["text"][:1000], links=clean["links"],
                meta={"likes": sn.get("likeCount", 0)}))
        return items

    def comment(self, target: str, text: str, confirm_cb: ConfirmCb) -> SendResult:
        vid = _yt_video_id(target)
        if not self.oauth:
            return SendResult(False, self.name, vid,
                              "posting needs YOUTUBE_OAUTH_TOKEN (OAuth2, "
                              "youtube.force-ssl scope)")
        preview = f"[YOUTUBE] comment on video {vid}\n\n{text}"
        if not confirm_cb(preview):
            return SendResult(False, self.name, vid, "not confirmed",
                              preview=preview)
        try:
            import requests
            r = requests.post(
                f"{self.BASE}/commentThreads", params={"part": "snippet"},
                headers={"Authorization": f"Bearer {self.oauth}"},
                json={"snippet": {"videoId": vid, "topLevelComment": {
                    "snippet": {"textOriginal": text}}}}, timeout=30)
            if r.status_code < 400:
                return SendResult(True, self.name, vid, "posted 1 comment",
                                  preview=preview)
            return SendResult(False, self.name, vid,
                              f"api {r.status_code}: {r.text[:150]}",
                              preview=preview)
        except Exception as exc:
            return SendResult(False, self.name, vid,
                              f"{type(exc).__name__}: {exc}", preview=preview)


# --- factory ----------------------------------------------------------------

PROVIDERS = ("email", "telegram", "instagram", "facebook", "threads", "youtube")


def get_provider(name: str) -> MessengerProvider | None:
    name = (name or "").lower()
    if name == "email":
        return EmailProvider()
    if name == "telegram":
        return TelegramProvider()
    if name in ("instagram", "facebook", "threads"):
        return MetaProvider(name)
    if name == "youtube":
        return YouTubeProvider()
    return None
