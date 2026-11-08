"""
Nova - All-in-One Multilingual AI Assistant (Streamlit + Hugging Face free inference)
Deploy on Hugging Face Spaces (SDK: Streamlit). Mobile-friendly.
"""
import base64
import hmac
import imaplib
import io
import json
import os
import re
import smtplib
import tempfile
import textwrap
import time
import email as email_lib
from datetime import datetime
from email.header import decode_header, make_header
from email.message import EmailMessage

import pandas as pd
import requests
import streamlit as st

# ----------------------------------------------------------------------------
# Page config + styling
# ----------------------------------------------------------------------------
st.set_page_config(page_title="Nova AI Assistant", page_icon="🤖",
                   layout="centered", initial_sidebar_state="collapsed")

st.markdown("""
<style>
.block-container{padding-top:1.2rem;padding-bottom:6rem;max-width:760px}
[data-testid="stChatMessage"] p,[data-testid="stChatMessage"] li{
  unicode-bidi:plaintext;text-align:start;line-height:1.75}
.stButton>button,.stDownloadButton>button{width:100%;border-radius:12px;min-height:2.8rem}
</style>
""", unsafe_allow_html=True)

# ----------------------------------------------------------------------------
# Constants
# ----------------------------------------------------------------------------
# Optional fallback token that survives browser refreshes. WARNING: anyone who can read your code can read it,
# so only fill this in on a PRIVATE Space. A Space secret named HF_TOKEN is the safer option.
DEFAULT_HF_TOKEN = ""

# Ungated chat models, in fallback order. Availability on the free tier changes over time:
# use Settings -> "Find live free chat models" to list what Hugging Face serves right now.
MODELS = [
    "Qwen/Qwen2.5-7B-Instruct",
    "Qwen/Qwen2.5-72B-Instruct",
    "Qwen/Qwen2.5-Coder-32B-Instruct",
    "deepseek-ai/DeepSeek-R1-Distill-Qwen-1.5B",
]

M_CHAT = "💬 Chat"
M_RES = "🌐 Web Research"
M_VID = "🎬 Video Studio"
M_FREE = "💼 Freelance Suite"
M_XLS = "📊 Excel / CSV"
M_MAIL = "📧 Gmail"
MODES = [M_CHAT, M_RES, M_VID, M_FREE, M_XLS, M_MAIL]

CRED_FIELDS = {
    "HF_TOKEN": "Hugging Face token (needs 'Inference Providers' permission)",
    "GMAIL_ADDRESS": "Gmail address",
    "GMAIL_APP_PASSWORD": "Gmail App Password (16 chars, NOT your normal password)",
    "YOUTUBE_API_KEY": "YouTube Data API key (Google Cloud)",
    "INSTAGRAM_ACCESS_TOKEN": "Instagram Graph API access token",
    "TIKTOK_ACCESS_TOKEN": "TikTok API access token",
}
TESTABLE = {"HF_TOKEN", "GMAIL_APP_PASSWORD", "YOUTUBE_API_KEY", "INSTAGRAM_ACCESS_TOKEN"}

FREELANCE_TASKS = {
    "Client proposal": "Write a persuasive, tailored freelance proposal: a hook that shows you understood the "
                       "client's problem, proposed approach, deliverables, timeline, pricing options, and a clear "
                       "call to action. Keep it concise and professional.",
    "Outreach / cold email": "Write 3 subject-line options, one short personalised cold outreach email (under 150 "
                             "words), and one follow-up email for 3 days later.",
    "Client reply / communication": "Draft a polite, professional reply to the client message below. Offer a "
                                    "short version and a detailed version.",
    "Deep research": "Do deep research on the topic and produce a structured report: summary, key findings, "
                     "data points, risks, and recommendations. Cite sources as [1], [2].",
}

VOICE_LANGS = {
    "English": "en", "Urdu (اردو)": "ur", "Roman Urdu (read with Hindi voice)": "hi",
    "Hindi": "hi", "Arabic": "ar", "Spanish": "es", "French": "fr", "German": "de",
    "Turkish": "tr", "Indonesian": "id", "Bengali": "bn",
}

XLS_INSTR = (
    "Return ONLY one valid JSON object, no prose, no markdown fences, in exactly this shape: "
    '{"filename":"name.xlsx","sheets":[{"name":"Sheet1","columns":["Col A","Col B"],"rows":[["x",1]]}]} '
    "Use real numbers for numeric cells (not strings). For calculated cells you may use Excel formulas written as "
    "strings starting with '=' (for example \"=SUM(B2:B10)\"). Write headers and text in the language the user "
    "used. Fill in complete, realistic data."
)

VID_INSTR = (
    "Return ONLY one valid JSON object, no prose, no markdown fences, in exactly this shape: "
    '{"title":"...","hook":"...","caption":"...","hashtags":["tag1","tag2"],'
    '"voiceover_prompt":"style/voice direction for an AI voice",'
    '"scenes":[{"narration":"spoken words","on_screen_text":"short big text (max 8 words)",'
    '"visual_idea":"what to show"}]} '
    "Make narration natural, with a strong hook in scene 1 and a call to action in the last scene."
)


# ----------------------------------------------------------------------------
# State, secrets, access gate
# ----------------------------------------------------------------------------
def init_state():
    ss = st.session_state
    ss.setdefault("vault", {})
    ss.setdefault("messages", [])
    ss.setdefault("inbox", [])
    ss.setdefault("authed", False)


def _st_secret(name):
    try:
        v = st.secrets.get(name)
        return str(v).strip() if v else ""
    except Exception:  # noqa: BLE001  (no secrets.toml present)
        return ""


def secret(name, default=""):
    """Lookup order: session vault -> DEFAULT_HF_TOKEN (HF_TOKEN only) -> st.secrets -> os.environ."""
    v = st.session_state.get("vault", {}).get(name)
    if v:
        return v.strip()
    if name == "HF_TOKEN" and DEFAULT_HF_TOKEN.strip():
        return DEFAULT_HF_TOKEN.strip()
    return _st_secret(name) or os.environ.get(name, default).strip()


def secret_source(name):
    """Where a credential currently comes from (for the Credentials tab)."""
    if st.session_state.get("vault", {}).get(name):
        return "session"
    if name == "HF_TOKEN" and DEFAULT_HF_TOKEN.strip():
        return "DEFAULT_HF_TOKEN in code"
    if _st_secret(name):
        return "st.secrets"
    if os.environ.get(name):
        return "Space secret"
    return None


def gate():
    """Optional password lock. Set APP_PASSWORD in Space secrets to enable."""
    pw = os.environ.get("APP_PASSWORD")
    if not pw or st.session_state.get("authed"):
        return
    st.title("🔒 Nova AI Assistant")
    entered = st.text_input("Password", type="password")
    if st.button("Unlock"):
        if hmac.compare_digest(entered.encode(), pw.encode()):
            st.session_state.authed = True
            st.rerun()
        else:
            st.error("Wrong password.")
    st.stop()


# ----------------------------------------------------------------------------
# Encrypted vault export / import
# ----------------------------------------------------------------------------
def _fernet(passphrase, salt):
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=390_000)
    return Fernet(base64.urlsafe_b64encode(kdf.derive(passphrase.encode())))


def encrypt_vault(vault, passphrase):
    salt = os.urandom(16)
    token = _fernet(passphrase, salt).encrypt(json.dumps(vault).encode())
    return base64.b64encode(salt + token)


def decrypt_vault(blob, passphrase):
    raw = base64.b64decode(blob)
    salt, token = raw[:16], raw[16:]
    return json.loads(_fernet(passphrase, salt).decrypt(token).decode())


# ----------------------------------------------------------------------------
# LLM (Hugging Face free inference)
# ----------------------------------------------------------------------------
def _client():
    """Hugging Face serverless Inference Providers client (provider chosen automatically)."""
    from huggingface_hub import InferenceClient
    token = secret("HF_TOKEN") or None
    try:
        return InferenceClient(provider="auto", token=token, timeout=120)
    except TypeError:  # very old huggingface_hub without the provider argument
        return InferenceClient(token=token, timeout=120)


def _raw_stream(model, messages, max_tokens, temperature):
    for chunk in _client().chat_completion(messages=messages, model=model, max_tokens=max_tokens,
                                           temperature=temperature, stream=True):
        if chunk.choices and chunk.choices[0].delta and chunk.choices[0].delta.content:
            yield chunk.choices[0].delta.content


def _partial_len(buf, tag):
    """Length of the longest suffix of buf that is a proper prefix of tag (tag split across chunks)."""
    for k in range(min(len(tag) - 1, len(buf)), 0, -1):
        if buf.endswith(tag[:k]):
            return k
    return 0


def _strip_think(tokens):
    """Hides <think>...</think> reasoning blocks (DeepSeek-R1 style) from the visible answer."""
    buf, in_think = "", False
    for tok in tokens:
        buf += tok
        while True:
            if not in_think:
                i = buf.find("<think>")
                if i >= 0:
                    if buf[:i]:
                        yield buf[:i]
                    buf = buf[i + 7:]
                    in_think = True
                    continue
                keep = _partial_len(buf, "<think>")
                out = buf[:len(buf) - keep]
                if out:
                    yield out
                buf = buf[len(buf) - keep:]
                break
            i = buf.find("</think>")
            if i >= 0:
                buf = buf[i + 8:].lstrip()
                in_think = False
                continue
            keep = _partial_len(buf, "</think>")
            buf = buf[len(buf) - keep:]
            break
    if buf and not in_think:
        yield buf


class LLMError(Exception):
    """An error whose message is safe and helpful to show directly to the user."""


AUTH_MSG = (
    "🔐 **Hugging Face rejected your token (401/403).** This is a token-permission problem, so switching "
    "models cannot fix it.\n\n"
    "1. Open huggingface.co/settings/tokens → **Create new token** → type **Fine-grained**.\n"
    "2. Tick **Make calls to Inference Providers** (under *User permissions*). A plain *Read* token also works.\n"
    "3. Paste the new token in the **Credentials** tab (or in `DEFAULT_HF_TOKEN`, or as the `HF_TOKEN` "
    "secret), then tap **Test connection**.\n\n"
    "Also make sure no old `HF_TOKEN` secret is overriding the new one."
)
CREDITS_MSG = (
    "💳 **Free inference credits are used up (402).** Wait for the monthly reset, use a different Hugging Face "
    "account's token, or choose a smaller model in Settings."
)


def _short_err(e):
    return re.sub(r"\s+", " ", str(e))[:170]


def _status(e):
    """HTTP status code behind an exception, if any."""
    code = getattr(getattr(e, "response", None), "status_code", None)
    if code:
        return int(code)
    m = re.search(r"\b(400|401|402|403|404|429|500|502|503)\b", str(e))
    return int(m.group(1)) if m else None


def _candidates(model):
    out = []
    for m in [model] + MODELS:
        if m and m not in out:
            out.append(m)
    return out


def stream_llm(messages, model, max_tokens=1500, temperature=0.7):
    """Streams text. Rate-limited/unsupported models fall through to the next model in MODELS;
    authentication or credit problems stop immediately with a clear message."""
    errors = []
    for m in _candidates(model):
        started = False
        try:
            for piece in _strip_think(_raw_stream(m, messages, max_tokens, temperature)):
                started = True
                yield piece
            if started:
                return
            errors.append(f"{m}: empty reply")
        except Exception as e:  # noqa: BLE001
            if started:
                return  # keep the partial answer rather than crash
            code = _status(e)
            if code in (401, 403):
                raise LLMError(AUTH_MSG) from e
            if code == 402:
                raise LLMError(CREDITS_MSG) from e
            reason = {429: "rate-limited", 404: "not available", 400: "not a supported chat model"}.get(
                code, _short_err(e))
            errors.append(f"{m}: {reason}")
    raise LLMError(
        "⚠️ No model could answer right now (they are busy, rate-limited or not served for free).\n\n"
        + "\n".join(f"- `{x}`" for x in errors)
        + "\n\nTry again in a minute, or open **Settings → Find live free chat models**.")


def ask(messages, model, **kw):
    return "".join(stream_llm(messages, model, **kw))


def system_prompt():
    profile = st.session_state.get("profile_text", "").strip()
    sp = (
        "You are Nova, a capable, friendly all-in-one AI assistant and agent.\n"
        "LANGUAGE RULE: detect the language AND script of the user's latest message and reply in the same one. "
        "Urdu script -> reply in Urdu script. Roman Urdu (Urdu written in Latin letters) -> reply in Roman Urdu. "
        "Any other language -> reply in that language. Switch language only if the user asks.\n"
        "Be accurate and practical. When web results are provided, base facts on them and cite as [1], [2]. "
        "Never invent facts, links, or statistics; say when you are unsure. "
        f"Today's date is {datetime.now().strftime('%A, %d %B %Y')}."
    )
    if profile:
        sp += f"\nAbout the user / their services (use when relevant):\n{profile}"
    return sp


def parse_json(text):
    m = re.search(r"\{.*\}", text, re.S)
    if not m:
        raise ValueError("The model did not return JSON. Try again or pick another model.")
    s = m.group(0)
    try:
        return json.loads(s)
    except json.JSONDecodeError:
        return json.loads(re.sub(r",\s*([}\]])", r"\1", s))


# ----------------------------------------------------------------------------
# Web search / browsing
# ----------------------------------------------------------------------------
def web_search(query, n=5):
    try:
        try:
            from ddgs import DDGS
        except ImportError:
            from duckduckgo_search import DDGS
        with DDGS() as d:
            res = list(d.text(query, max_results=n))
        return [{"title": r.get("title", ""), "url": r.get("href", ""), "text": r.get("body", "")} for r in res]
    except Exception:  # noqa: BLE001
        return []


def fetch_page(url, limit=3000):
    if not url or not url.startswith(("http://", "https://")):
        return ""
    try:
        from bs4 import BeautifulSoup
        r = requests.get(url, headers={"User-Agent": "Mozilla/5.0 (compatible; NovaBot/1.0)"}, timeout=10)
        if "html" not in r.headers.get("content-type", ""):
            return ""
        soup = BeautifulSoup(r.text, "html.parser")
        for t in soup(["script", "style", "nav", "footer", "header", "aside", "noscript"]):
            t.decompose()
        return re.sub(r"\s+", " ", soup.get_text(" ")).strip()[:limit]
    except Exception:  # noqa: BLE001
        return ""


def gather(query, deep=False):
    items = []
    for u in re.findall(r"https?://[^\s)>\]]+", query)[:2]:
        txt = fetch_page(u, 4000)
        if txt:
            items.append({"title": u, "url": u, "text": txt})
    results = web_search(query, 8 if deep else 5)
    for idx, r in enumerate(results):
        if deep and idx < 3:
            page = fetch_page(r["url"], 3000)
            if page:
                r["text"] = r["text"] + "\n" + page
        items.append(r)
    ctx = "\n\n".join(f"[{n}] {it['title']}\n{it['url']}\n{it['text']}" for n, it in enumerate(items, 1))
    sources = [{"title": it["title"] or it["url"], "url": it["url"]} for it in items]
    return ctx, sources


def needs_web(q, model):
    try:
        r = ask([{"role": "system", "content": "Answer only YES or NO. Does answering the user's message need "
                  "fresh or real-time facts from the internet (news, prices, weather, recent events, 'latest', "
                  "specific web pages, current people/positions)?"},
                 {"role": "user", "content": q}], model, max_tokens=4, temperature=0)
        return r.strip().upper().startswith("YES")
    except Exception:  # noqa: BLE001
        return False


def discover_models(limit=12):
    """Asks the Hugging Face Hub which chat models are currently served by Inference Providers (ungated only)."""
    params = [("inference_provider", "all"), ("pipeline_tag", "text-generation"), ("filter", "conversational"),
              ("sort", "likes"), ("limit", "60"), ("expand[]", "gated")]
    headers = {"Authorization": f"Bearer {secret('HF_TOKEN')}"} if secret("HF_TOKEN") else {}
    r = requests.get("https://huggingface.co/api/models", params=params, headers=headers, timeout=20)
    if not r.ok:
        raise RuntimeError(f"Hub returned HTTP {r.status_code}")
    return [m["id"] for m in r.json() if m.get("id") and not m.get("gated")][:limit]


# ----------------------------------------------------------------------------
# Excel / CSV builder
# ----------------------------------------------------------------------------
def build_workbook(spec, fmt):
    from openpyxl.styles import Font
    from openpyxl.utils import get_column_letter
    sheets = spec.get("sheets") or []
    if not sheets:
        raise ValueError("No sheets returned by the model.")
    frames = []
    for s in sheets:
        cols = [str(c) for c in (s.get("columns") or [])]
        width = len(cols)
        if not width:
            continue
        rows = [(list(r) + [""] * width)[:width] for r in (s.get("rows") or []) if isinstance(r, list)]
        name = re.sub(r"[\[\]:*?/\\]", "", str(s.get("name") or "Sheet"))[:31] or "Sheet"
        frames.append((name, pd.DataFrame(rows, columns=cols)))
    if not frames:
        raise ValueError("The model returned empty tables.")
    base = re.sub(r"[^\w\-]+", "_", os.path.splitext(str(spec.get("filename") or "data"))[0]).strip("_") or "data"

    if fmt == "csv":
        data = frames[0][1].to_csv(index=False).encode("utf-8-sig")
        return f"{base}.csv", data, "text/csv", frames[:1]

    buf = io.BytesIO()
    with pd.ExcelWriter(buf, engine="openpyxl") as writer:
        used = set()
        for name, df in frames:
            n, k = name, 1
            while n in used:
                k += 1
                n = f"{name[:28]}_{k}"
            used.add(n)
            df.to_excel(writer, sheet_name=n, index=False)
            ws = writer.sheets[n]
            for c in ws[1]:
                c.font = Font(bold=True)
            for i, col in enumerate(df.columns, 1):
                longest = max([len(str(col))] + [len(str(v)) for v in df.iloc[:, i - 1].tolist()])
                ws.column_dimensions[get_column_letter(i)].width = min(60, longest + 3)
    return (f"{base}.xlsx", buf.getvalue(),
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", frames)


# ----------------------------------------------------------------------------
# Video assembly (gTTS voiceover + text slides via moviepy)
# ----------------------------------------------------------------------------
PALETTES = [((24, 28, 60), (98, 54, 160)), ((10, 70, 90), (30, 160, 140)),
            ((90, 20, 50), (220, 90, 70)), ((20, 40, 25), (70, 150, 80))]
FONTS = ["/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
         "/usr/share/fonts/dejavu/DejaVuSans-Bold.ttf", "DejaVuSans-Bold.ttf",
         "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf"]


def _font(size):
    from PIL import ImageFont
    for p in FONTS:
        try:
            return ImageFont.truetype(p, size)
        except Exception:  # noqa: BLE001
            continue
    return ImageFont.load_default()


def _shape(line):
    if re.search(r"[\u0600-\u06FF]", line):
        try:
            import arabic_reshaper
            try:
                from bidi import get_display
            except ImportError:
                from bidi.algorithm import get_display
            return get_display(arabic_reshaper.reshape(line))
        except Exception:  # noqa: BLE001
            return line
    return line


def make_slide(text, idx, total, size):
    import numpy as np
    from PIL import Image, ImageDraw
    w, h = size
    c1, c2 = PALETTES[idx % len(PALETTES)]
    t = np.linspace(0, 1, h)[:, None, None]
    grad = np.array(c1)[None, None, :] * (1 - t) + np.array(c2)[None, None, :] * t
    img = Image.fromarray(np.repeat(grad, w, axis=1).astype("uint8"))
    d = ImageDraw.Draw(img)
    font = _font(int(w * 0.075))
    lines = [_shape(l) for l in textwrap.wrap(str(text), width=20)[:9]] or [""]
    lh = int(getattr(font, "size", 40) * 1.4)
    y = (h - lh * len(lines)) // 2
    for ln in lines:
        tw = d.textlength(ln, font=font)
        d.text(((w - tw) / 2, y), ln, font=font, fill="white")
        y += lh
    small = _font(int(w * 0.035))
    d.text((w * 0.06, h * 0.94), f"{idx + 1}/{total}", font=small, fill=(230, 230, 230))
    return img


def build_video(plan, lang, size=(720, 1280), fps=12):
    import numpy as np
    from gtts import gTTS
    from moviepy.editor import AudioFileClip, ImageClip, concatenate_videoclips
    scenes = plan.get("scenes") or []
    if not scenes:
        raise ValueError("No scenes in the plan.")
    tmp = tempfile.mkdtemp()
    clips, audios = [], []
    for i, sc in enumerate(scenes):
        narr = (sc.get("narration") or sc.get("on_screen_text") or ".").strip()
        mp3 = os.path.join(tmp, f"s{i}.mp3")
        gTTS(text=narr, lang=lang).save(mp3)
        audio = AudioFileClip(mp3)
        audios.append(audio)
        slide = make_slide(sc.get("on_screen_text") or narr, i, len(scenes), size)
        clips.append(ImageClip(np.array(slide)).set_duration(audio.duration + 0.4).set_audio(audio))
    final = concatenate_videoclips(clips, method="compose")
    out = os.path.join(tmp, "video.mp4")
    final.write_videofile(out, fps=fps, codec="libx264", audio_codec="aac", preset="ultrafast",
                          temp_audiofile=os.path.join(tmp, "tmp_audio.m4a"), logger=None)
    for c in clips + audios:
        try:
            c.close()
        except Exception:  # noqa: BLE001
            pass
    with open(out, "rb") as f:
        return f.read()


def format_plan(p):
    out = [f"### 🎬 {p.get('title', 'Video plan')}", f"**Hook:** {p.get('hook', '')}", ""]
    for n, s in enumerate(p.get("scenes", []), 1):
        out.append(f"**Scene {n}** 🎤 {s.get('narration', '')}\n\n"
                   f"🖼️ *On screen:* {s.get('on_screen_text', '')}  ·  🎥 *Visual:* {s.get('visual_idea', '')}\n")
    out.append(f"**Caption:** {p.get('caption', '')}")
    tags = " ".join("#" + str(t).lstrip("#") for t in p.get("hashtags", []))
    out.append(f"**Hashtags:** {tags}")
    if p.get("voiceover_prompt"):
        out.append(f"\n**Voiceover prompt:** {p['voiceover_prompt']}")
    return "\n".join(out)


# ----------------------------------------------------------------------------
# Gmail (IMAP/SMTP with an App Password - official, no scraping)
# ----------------------------------------------------------------------------
def imap_connect():
    addr = secret("GMAIL_ADDRESS")
    pw = secret("GMAIL_APP_PASSWORD").replace(" ", "")
    if not addr or not pw:
        raise RuntimeError("Add your Gmail address and App Password in the Credentials tab first.")
    m = imaplib.IMAP4_SSL("imap.gmail.com")
    m.login(addr, pw)
    return m


def _hdr(v):
    try:
        return str(make_header(decode_header(v or "")))
    except Exception:  # noqa: BLE001
        return v or ""


def _part_text(part):
    payload = part.get_payload(decode=True) or b""
    return payload.decode(part.get_content_charset() or "utf-8", errors="replace")


def _body(msg):
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain" and "attachment" not in str(part.get("Content-Disposition", "")):
                return _part_text(part)
        for part in msg.walk():
            if part.get_content_type() == "text/html":
                return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", _part_text(part)))
        return ""
    return _part_text(msg)


def fetch_inbox(n=10, unread=False):
    m = imap_connect()
    out = []
    try:
        m.select("INBOX", readonly=True)
        _, data = m.search(None, "UNSEEN" if unread else "ALL")
        ids = data[0].split()[-n:][::-1]
        for i in ids:
            _, md = m.fetch(i, "(BODY.PEEK[])")
            msg = email_lib.message_from_bytes(md[0][1])
            out.append({"from": _hdr(msg.get("From")), "subject": _hdr(msg.get("Subject")),
                        "date": msg.get("Date", ""), "body": re.sub(r"\s+", " ", _body(msg)).strip()[:1500]})
    finally:
        try:
            m.logout()
        except Exception:  # noqa: BLE001
            pass
    return out


def _compose(to, subject, body):
    msg = EmailMessage()
    msg["From"] = secret("GMAIL_ADDRESS")
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(body)
    return msg


def save_draft(to, subject, body):
    msg = _compose(to, subject, body)
    m = imap_connect()
    try:
        typ, _ = m.append('"[Gmail]/Drafts"', "\\Draft", imaplib.Time2Internaldate(time.time()), msg.as_bytes())
    finally:
        try:
            m.logout()
        except Exception:  # noqa: BLE001
            pass
    if typ != "OK":
        raise RuntimeError("Gmail refused to save the draft (is your Gmail language English?).")


def send_mail(to, subject, body):
    msg = _compose(to, subject, body)
    with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=30) as s:
        s.login(secret("GMAIL_ADDRESS"), secret("GMAIL_APP_PASSWORD").replace(" ", ""))
        s.send_message(msg)


# ----------------------------------------------------------------------------
# Credential tests
# ----------------------------------------------------------------------------
def test_connection(key):
    try:
        if key == "HF_TOKEN":
            r = requests.get("https://huggingface.co/api/whoami-v2",
                             headers={"Authorization": f"Bearer {secret(key)}"}, timeout=15)
            if not r.ok:
                return False, f"Token invalid (HTTP {r.status_code})."
            who = r.json().get("name")
            try:
                _client().chat_completion(messages=[{"role": "user", "content": "hi"}], model=MODELS[0],
                                          max_tokens=1)
            except Exception as e:  # noqa: BLE001
                code = _status(e)
                if code in (401, 403):
                    return False, (f"Token is valid (user {who}) but has NO Inference Providers permission. "
                                   "Create a fine-grained token with 'Make calls to Inference Providers'.")
                if code == 402:
                    return False, "Token OK, but free inference credits are used up."
                return True, f"Token valid (user {who}); test call to {MODELS[0]} said: {_short_err(e)}"
            return True, f"Logged in as {who}; inference works ✅"
        if key == "GMAIL_APP_PASSWORD":
            m = imap_connect()
            m.logout()
            return True, "Gmail login OK"
        if key == "YOUTUBE_API_KEY":
            r = requests.get("https://www.googleapis.com/youtube/v3/search",
                             params={"part": "snippet", "q": "test", "maxResults": 1, "key": secret(key)}, timeout=15)
            return r.ok, "YouTube key OK" if r.ok else f"HTTP {r.status_code}: {r.text[:120]}"
        if key == "INSTAGRAM_ACCESS_TOKEN":
            r = requests.get("https://graph.instagram.com/me",
                             params={"fields": "id,username", "access_token": secret(key)}, timeout=15)
            return r.ok, f"Instagram: @{r.json().get('username')}" if r.ok else f"HTTP {r.status_code}: {r.text[:120]}"
    except Exception as e:  # noqa: BLE001
        return False, str(e)
    return False, "No test available"


# ----------------------------------------------------------------------------
# Message rendering
# ----------------------------------------------------------------------------
def render_extras(i, msg):
    if msg.get("sources"):
        with st.expander("🔗 Sources"):
            for n, s in enumerate(msg["sources"], 1):
                st.markdown(f"{n}. [{s['title'][:80]}]({s['url']})")
    for name, df in msg.get("preview", []):
        st.caption(f"Preview: {name}")
        st.dataframe(df, use_container_width=True)
    for j, f in enumerate(msg.get("files", [])):
        st.download_button(f"⬇️ Download {f['name']}", f["data"], file_name=f["name"], mime=f["mime"],
                           key=f"dl_{i}_{j}")
    if msg.get("video_plan"):
        if not msg.get("video"):
            if st.button("🎞️ Assemble video (voiceover + slides)", key=f"asm_{i}"):
                with st.spinner("Building video… this can take a few minutes on the free CPU."):
                    try:
                        msg["video"] = build_video(msg["video_plan"], msg.get("voice_lang", "en"))
                    except Exception as e:  # noqa: BLE001
                        st.error(f"Video build failed: {e}")
        if msg.get("video"):
            st.video(msg["video"])
            st.download_button("⬇️ Download video (MP4)", msg["video"], file_name="video.mp4",
                               mime="video/mp4", key=f"vdl_{i}")


def build_history(n=8):
    """Recent turns for the model; failed turns (and the prompt that caused them) are left out."""
    msgs = st.session_state.messages
    out = []
    for idx, m in enumerate(msgs):
        if m.get("error"):
            continue
        if m["role"] == "user" and idx + 1 < len(msgs) and msgs[idx + 1].get("error"):
            continue
        out.append({"role": m["role"], "content": m["content"][:3000]})
    return out[-n:]


def render_body(m):
    if m.get("error") == "warning":
        st.warning(m["content"])
    elif m.get("error"):
        st.error(m["content"])
    else:
        st.markdown(m["content"])


# ----------------------------------------------------------------------------
# Main request handler
# ----------------------------------------------------------------------------
def handle(prompt, mode, opts, model, temp, auto_search):
    ss = st.session_state
    hist = build_history()
    ss.messages.append({"role": "user", "content": prompt})
    with st.chat_message("user"):
        st.markdown(prompt)

    with st.chat_message("assistant"):
        extra = {}
        sources = []
        content = ""
        try:
            sys_msg = system_prompt()
            user_content = prompt
            json_mode = False
            max_tokens = 1600

            if mode == M_CHAT:
                if auto_search and needs_web(prompt, model):
                    with st.spinner("🌐 Searching the web…"):
                        ctx, sources = gather(prompt)
                    if ctx:
                        user_content = f"WEB RESULTS (cite as [n]):\n{ctx}\n\nUSER MESSAGE:\n{prompt}"

            elif mode == M_RES:
                with st.spinner("🌐 Researching the web (reading pages)…"):
                    ctx, sources = gather(prompt, deep=True)
                user_content = (f"WEB RESULTS (cite as [n]):\n{ctx}\n\nTASK: Write a well-structured research "
                                f"report answering the request. Include key findings, numbers, caveats and "
                                f"a short conclusion.\n\nREQUEST:\n{prompt}")
                max_tokens = 2200

            elif mode == M_FREE:
                task = opts.get("task", "Client proposal")
                ctx = ""
                if task == "Deep research":
                    with st.spinner("🌐 Researching…"):
                        ctx, sources = gather(prompt, deep=True)
                    ctx = f"WEB RESULTS (cite as [n]):\n{ctx}\n\n"
                user_content = f"{ctx}TASK: {FREELANCE_TASKS[task]}\n\nDETAILS FROM USER:\n{prompt}"
                max_tokens = 2200

            elif mode == M_XLS:
                json_mode = True
                user_content = f"{XLS_INSTR}\n\nUSER REQUEST:\n{prompt}"
                max_tokens = 3500

            elif mode == M_VID:
                json_mode = True
                lang_name = opts.get("voice_name", "English")
                n_scenes = max(3, int(opts.get("duration", 30)) // 6)
                user_content = (f"{VID_INSTR}\n\nPlatform: {opts.get('platform')}. Target length: "
                                f"{opts.get('duration')} seconds (~{n_scenes} scenes). Write narration and "
                                f"on-screen text in: {lang_name}. Idea/topic:\n{prompt}")
                max_tokens = 2500

            elif mode == M_MAIL:
                box = "\n\n".join(f"#{n} From: {e['from']}\nSubject: {e['subject']}\nDate: {e['date']}\n{e['body']}"
                                  for n, e in enumerate(ss.inbox, 1)) or "(No emails fetched yet.)"
                sys_msg += ("\nYou help manage the user's Gmail. Emails below were fetched read-only. Summarise, "
                            "prioritise and draft replies. Never claim to have sent anything - the user sends or "
                            "saves drafts with the buttons.")
                user_content = f"INBOX:\n{box}\n\nUSER REQUEST:\n{prompt}"

            messages = [{"role": "system", "content": sys_msg}] + hist + [{"role": "user", "content": user_content}]

            if json_mode:
                with st.spinner("⚙️ Working…"):
                    raw = ask(messages, model, max_tokens=max_tokens, temperature=0.3)
                if mode == M_XLS:
                    spec = parse_json(raw)
                    fname, data, mime, frames = build_workbook(spec, opts.get("fmt", "xlsx"))
                    content = f"✅ **{fname}** is ready ({len(frames)} sheet(s)). Tap download below."
                    extra = {"files": [{"name": fname, "data": data, "mime": mime}],
                             "preview": [(n, df.head(15).astype(str)) for n, df in frames]}
                else:
                    plan = parse_json(raw)
                    content = format_plan(plan)
                    extra = {"video_plan": plan, "voice_lang": opts.get("voice_code", "en")}
                st.markdown(content)
            else:
                ph = st.empty()
                acc = ""
                for tok in stream_llm(messages, model, max_tokens=max_tokens, temperature=temp):
                    acc += tok
                    ph.markdown(acc + "▌")
                ph.markdown(acc)
                content = acc
        except LLMError as e:
            level, content, sources, extra = "error", str(e), [], {}
            st.error(content)
        except (ValueError, KeyError, TypeError, json.JSONDecodeError) as e:
            level, sources, extra = "warning", [], {}
            content = (f"⚠️ The model's answer could not be turned into the requested format ({_short_err(e)}). "
                       "Please try again, or pick another model in Settings.")
            st.warning(content)
        except Exception as e:  # noqa: BLE001
            level, sources, extra = "warning", [], {}
            content = f"⚠️ Something went wrong: {_short_err(e)}. Please try again."
            st.warning(content)
        else:
            level = None

        msg = {"role": "assistant", "content": content, "sources": sources, "error": level, **extra}
        ss.messages.append(msg)
        render_extras(len(ss.messages) - 1, msg)


# ----------------------------------------------------------------------------
# UI
# ----------------------------------------------------------------------------
init_state()
gate()

st.title("🤖 Nova AI Assistant")
tab_chat, tab_cred, tab_set = st.tabs(["💬 Assistant", "🔐 Credentials", "⚙️ Settings"])

# ---- Settings tab
with tab_set:
    if st.button("🔎 Find live free chat models"):
        try:
            with st.spinner("Asking Hugging Face…"):
                st.session_state.found_models = discover_models()
            st.success(f"Found {len(st.session_state.found_models)} models. They are now in the list below.")
        except Exception as e:  # noqa: BLE001
            st.warning(f"Could not list models right now: {_short_err(e)}")
    extra_models = [m for m in st.session_state.get("found_models", []) if m not in MODELS]
    preset = st.selectbox("AI model (free Hugging Face)", MODELS + extra_models + ["Custom…"], key="model_sel")
    if preset == "Custom…":
        model = st.text_input("Custom model ID (e.g. org/model-name)", key="model_custom").strip() or MODELS[0]
    else:
        model = preset
    temp = st.slider("Creativity", 0.0, 1.2, 0.7, 0.1)
    auto_search = st.toggle("Auto web search in Chat mode", value=True)
    st.text_area("About me / my services (used in proposals & emails)", key="profile_text", height=120,
                 placeholder="e.g. I'm a freelance video editor & copywriter, 4 years experience…")
    if not secret("HF_TOKEN"):
        st.warning("No Hugging Face token set. Add HF_TOKEN in the Credentials tab (or as a Space secret).")

# ---- Credentials tab
with tab_cred:
    st.info("🔐 Credentials stay in this browser session's server memory only. They are never written to disk "
            "or logged. Best practice: use **Space Secrets** for permanent keys, and official API tokens or "
            "Google **App Passwords**. Never enter your normal Instagram/TikTok/Gmail passwords, and 2-step "
            "verification should stay ON (this app never tries to bypass it).")
    with st.form("vault_form", clear_on_submit=True):
        new = {}
        for k, label in CRED_FIELDS.items():
            new[k] = st.text_input(label, type="default" if k == "GMAIL_ADDRESS" else "password",
                                   placeholder="✅ already set" if secret(k) else "not set", key=f"f_{k}")
        cname = st.text_input("Custom entry name (e.g. MY_SESSION_TOKEN)", key="f_cname")
        cval = st.text_input("Custom entry value", type="password", key="f_cval")
        if st.form_submit_button("💾 Save to this session"):
            for k, v in new.items():
                if v.strip():
                    st.session_state.vault[k] = v.strip()
            if cname.strip() and cval.strip():
                st.session_state.vault[re.sub(r"\W+", "_", cname.strip()).upper()] = cval.strip()
            st.success("Saved for this session.")

    st.subheader("Stored credentials")
    keys = list(CRED_FIELDS) + [x for x in st.session_state.vault if x not in CRED_FIELDS]
    shown = False
    for k in keys:
        where = secret_source(k)
        if not where:
            continue
        shown = True
        st.write(f"**{k}** — ✅ {where}")
        if k in TESTABLE and st.button("🔌 Test connection", key=f"t_{k}"):
            ok, info = test_connection(k)
            (st.success if ok else st.error)(info)
        if k in st.session_state.vault:
            st.button("🗑️ Remove", key=f"rm_{k}", on_click=lambda kk=k: st.session_state.vault.pop(kk, None))
    if not shown:
        st.caption("Nothing stored yet.")

    st.subheader("Encrypted backup")
    pp = st.text_input("Backup passphrase", type="password", key="vault_pp")
    if pp and st.session_state.vault:
        st.download_button("⬇️ Export encrypted vault", encrypt_vault(st.session_state.vault, pp),
                           file_name="nova_vault.enc", key="vault_dl")
    up = st.file_uploader("Import encrypted vault", key="vault_up")
    if up and pp and st.button("📥 Import"):
        try:
            st.session_state.vault.update(decrypt_vault(up.read(), pp))
            st.success("Imported.")
            st.rerun()
        except Exception:  # noqa: BLE001
            st.error("Wrong passphrase or invalid file.")

# ---- Assistant tab
with tab_chat:
    mode = st.selectbox("Mode", MODES, label_visibility="collapsed")
    opts = {}

    if mode == M_FREE:
        opts["task"] = st.selectbox("Task", list(FREELANCE_TASKS))
    elif mode == M_XLS:
        opts["fmt"] = st.radio("Format", ["xlsx", "csv"], horizontal=True)
    elif mode == M_VID:
        opts["platform"] = st.selectbox("Platform", ["YouTube Shorts", "TikTok", "Instagram Reels",
                                                      "YouTube (long-form)"])
        opts["duration"] = st.select_slider("Length (seconds)", [15, 30, 45, 60, 90], value=30)
        opts["voice_name"] = st.selectbox("Script & voice language", list(VOICE_LANGS))
        opts["voice_code"] = VOICE_LANGS[opts["voice_name"]]
    elif mode == M_MAIL:
        c1, c2 = st.columns(2)
        n_mail = c1.number_input("How many emails", 1, 30, 10)
        unread = c2.checkbox("Unread only", value=False)
        if st.button("📥 Fetch inbox"):
            try:
                with st.spinner("Reading Gmail…"):
                    st.session_state.inbox = fetch_inbox(int(n_mail), unread)
                st.success(f"Fetched {len(st.session_state.inbox)} email(s).")
            except Exception as e:  # noqa: BLE001
                st.error(f"Gmail error: {e}")
        for n, e in enumerate(st.session_state.inbox, 1):
            with st.expander(f"{n}. {e['subject'][:60] or '(no subject)'}"):
                st.caption(f"{e['from']} · {e['date']}")
                st.write(e["body"][:600])

        def _use_last():
            last = [m for m in st.session_state.messages if m["role"] == "assistant"]
            if last:
                st.session_state["mail_body"] = last[-1]["content"]

        with st.expander("✍️ Compose / draft / send", expanded=False):
            st.text_input("To", key="mail_to")
            st.text_input("Subject", key="mail_sub")
            st.text_area("Body", key="mail_body", height=200)
            st.button("📋 Use last AI reply as body", on_click=_use_last)
            if st.button("💾 Save as Gmail draft"):
                try:
                    save_draft(st.session_state.mail_to, st.session_state.mail_sub, st.session_state.mail_body)
                    st.success("Saved to Gmail Drafts.")
                except Exception as e:  # noqa: BLE001
                    st.error(str(e))
            ok_send = st.checkbox("I reviewed this email and want to send it")
            if st.button("📤 Send now", disabled=not ok_send):
                try:
                    send_mail(st.session_state.mail_to, st.session_state.mail_sub, st.session_state.mail_body)
                    st.success("Sent ✅")
                except Exception as e:  # noqa: BLE001
                    st.error(str(e))

    if not st.session_state.messages:
        st.info("👋 Try: *Pakistan ki latest news batao* · *اردو میں یوٹیوب شارٹ کا اسکرپٹ لکھو* · "
                "*Make an Excel monthly budget* · *Write a proposal for a logo design client*")
    else:
        if st.button("🧹 Clear chat"):
            st.session_state.messages = []
            st.rerun()

    for i, m in enumerate(st.session_state.messages):
        with st.chat_message(m["role"]):
            render_body(m)
            if m["role"] == "assistant" and not m.get("error"):
                render_extras(i, m)

prompt = st.chat_input("Ask in اردو / Roman Urdu / English / any language…")
if prompt:
    with tab_chat:
        handle(prompt, mode, opts, model, temp, auto_search)
