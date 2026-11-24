#!/usr/bin/env python3
"""نظام إشارات الذهب — ClusterDelta فوتبرنت حقيقي.

القواعد مبنية على اختبار خلفي حقيقي (89 يوماً، 17910 شمعة، 21 نوفمبر 2026):
  • قواعد المخاطرة هي الحافة: +0.199R مقابل +0.018R بدونها، والتراجع -16.3R
    مقابل -38.5R. فهي ليست حماية فقط بل مصدر الربح.
  • الاختلال القطري سقط خارج العيّنة (+0.118R ضبط -> -0.070R اختبار): محذوف.
  • "دلتا >= 25% حجم كامل" غير مدعومة: الحد 18% بوابة فقط.
  • الامتصاص والمزاد غير المكتمل بلا أثر قابل للقياس: سياق لا قرار.
  • فلتر التقلب غير مطّرد بعد التطبيع: غير مطبّق.
  • دخول الكسر مستحيل رياضياً عند R:R 1:2، فالدخول ارتداد عند المستوى فقط.
"""
import base64, json, math, os, sqlite3, sys, time, traceback, urllib.parse
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils as au

BASE   = "https://orderflow.clusterdelta.com/api"
RELAY  = os.getenv("TS_RELAY", "")
DEV    = os.getenv("CD_DEVICE_FILE", "/var/lib/tradesys/device.json")
DB     = os.getenv("TS_DB", "/var/lib/tradesys/ts.db")
TF     = 5                 # دقائق لكل شمعة
OKX    = "https://www.okx.com/api/v5"

# أداتان، مصدران. ClusterDelta عقود آجلة فقط ولا تضمّ البتكوين.
INSTRUMENTS = {
    # tick: قيمة النقطة الواحدة بالدولار. pts: هدف النقاط التراكمي لليوم
    # (0 = لا هدف نقاط). rtarget: هدف اليوم بالـ R.
    "GC": {"src": "cd", "sym": "gc", "bucket": 0.1, "max": 6,
           "hours": "cme", "tick": 0.1, "pts": 600, "rtarget": 6.0,
           "name": "الذهب GC"},
    "BTC": {"src": "okx", "sym": "BTC-USDT-SWAP", "bucket": 10.0, "max": 6,
            "hours": "24/7", "tick": 1.0, "pts": 0, "rtarget": 6.0,
            "name": "البتكوين"},
}
WIN    = 36                # نافذة القرار: 3 ساعات (نفس نافذة الاختبار)
DELTA_MIN   = 0.18         # بوابة الدلتا
RR_MIN      = 2.0
MAX_TRADES  = 4
LOSS_CAP    = -2.0
DAY_TARGET  = 6.0         # افتراضي؛ كل أداة تتجاوزه بـ rtarget
MAX_CONSEC  = 2
MAX_AGE     = 900          # عمر آخر شمعة خمسية (ثانية)
SCAN        = 300
RIY = timezone(timedelta(hours=3))
CHI = ZoneInfo("America/Chicago")   # مرجع جلسة CME — يتبع التوقيت الصيفي تلقائياً
LON = ZoneInfo("Europe/London")     # بداية يوم التداول: افتتاح لندن 08:00
GROQ_KEY   = os.getenv("GROQ_KEY", "")
GROQ_MODEL = os.getenv("GROQ_MODEL", "openai/gpt-oss-120b")


# ── تليجرام ────────────────────────────────────────────────────────────
def say(text):
    if not RELAY:
        return False
    if len(text) > 3000:
        text = text[:1500] + "\n…\n" + text[-1200:]
    try:
        r = httpx.get(RELAY, params={"text": text}, timeout=25)
        return r.status_code == 200
    except Exception:
        return False


# ── عميل ClusterDelta ──────────────────────────────────────────────────
def b64u(b):
    return base64.b64encode(b).decode().replace("+", "-").replace("/", "_").rstrip("=")


class CD:
    def __init__(self):
        self.h = httpx.Client(timeout=30, follow_redirects=True,
                              headers={"User-Agent": "tradesys/2.0"})
        self.d = None
        if os.path.exists(DEV):
            try:
                self.d = json.load(open(DEV))
            except Exception:
                self.d = None

    def status(self):
        return self.h.get(f"{BASE}/auth.php", params={"action": "status"}).json()

    def register(self, login, pw):
        k = ec.generate_private_key(ec.SECP256R1())
        pem = k.private_bytes(serialization.Encoding.PEM,
                              serialization.PrivateFormat.PKCS8,
                              serialization.NoEncryption()).decode()
        pub = b64u(k.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo))
        sec = b64u(os.urandom(32))
        r = self.h.post(f"{BASE}/auth.php", params={"action": "login"},
                        data={"login": login, "password": pw, "pub": pub,
                              "secret": sec, "label": "tradesys, Linux", "id": ""})
        r.raise_for_status()
        o = r.json()
        if o.get("error") or not o.get("login"):
            raise RuntimeError(o.get("error") or "الدخول لم يُقبل")
        os.makedirs(os.path.dirname(DEV), exist_ok=True)
        self.d = {"id": o.get("device", ""), "secret": sec, "pem": pem}
        json.dump(self.d, open(DEV, "w"))
        os.chmod(DEV, 0o600)
        return {k2: v for k2, v in o.items() if k2 != "device"}

    def resume(self):
        """WebCrypto يُخرج r||s خاماً؛ cryptography تُخرج DER. بلا التحويل: 401."""
        if not self.d or not self.d.get("id"):
            return None
        for _ in range(2):
            n = self.h.get(f"{BASE}/auth.php", params={"action": "challenge"}).json().get("nonce")
            if not n:
                return None
            key = serialization.load_pem_private_key(self.d["pem"].encode(), None)
            der = key.sign(f"cdof-resume|{self.d['id']}|{n}".encode(),
                           ec.ECDSA(hashes.SHA256()))
            r_, s_ = au.decode_dss_signature(der)
            sig = b64u(r_.to_bytes(32, "big") + s_.to_bytes(32, "big"))
            r = self.h.post(f"{BASE}/auth.php", params={"action": "resume"},
                            data={"id": self.d["id"], "nonce": n, "sig": sig,
                                  "secret": self.d["secret"]})
            if r.status_code in (401, 403):
                return None
            if r.status_code == 409:
                st = self.status()
                if st.get("login"):
                    return st
                continue
            r.raise_for_status()
            return r.json()
        return None

    def ensure(self):
        """جلسة صالحة، مع إعادة تسجيل تلقائية عند إلغاء الجهاز.

        ClusterDelta تربط الجلسة بجهاز واحد: أي دخول من المتصفح يُلغي جهاز
        السيرفر ويوقف الذهب. التسجيل اليدوي كل مرة غير عملي، فإن توفّرت
        بيانات الدخول في ملف البيئة نعيد التسجيل مرة واحدة تلقائياً.
        """
        st = self.status()
        if st.get("login"):
            return st
        st = self.resume()
        if st and st.get("login"):
            return st
        login, pw = os.getenv("CD_LOGIN", ""), os.getenv("CD_PASSWORD", "")
        if login and pw:
            now = int(time.time())
            # لا نكرر محاولة فاشلة أكثر من مرة كل عشر دقائق
            if now - getattr(self, "_last_reg", 0) > 600:
                self._last_reg = now
                try:
                    out = self.register(login, pw)
                    say(f"🔑 أُعيد تسجيل جهاز ClusterDelta تلقائياً — "
                        f"{out.get('login')} · ينتهي {out.get('expiration')}")
                    return out
                except Exception as e:
                    raise RuntimeError(
                        f"فشل إعادة التسجيل التلقائي لـ ClusterDelta: {e}")
        raise RuntimeError("لا جلسة ClusterDelta — سجّل الجهاز، أو ضع "
                           "CD_LOGIN و CD_PASSWORD في /etc/tradesys.env "
                           "ليُعاد التسجيل تلقائياً")

    def bars(self, minutes=600):
        """المستويات [تكّات, Ask=شراء, Bid=بيع]؛ السعر = التكّات × tickSize."""
        to = int(time.time())
        r = self.h.get(f"{BASE}/footprint.php",
                       params={"symbol": INSTRUMENTS["GC"]["sym"], "tf": TF,
                               "from": to - minutes * 60, "to": to})
        if r.status_code in (401, 403):
            self.ensure()
            r = self.h.get(f"{BASE}/footprint.php",
                           params={"symbol": INSTRUMENTS["GC"]["sym"], "tf": TF,
                                   "from": to - minutes * 60, "to": to})
        r.raise_for_status()
        j = r.json()
        tick = j.get("tickSize") or 0
        out = []
        for b in j.get("bars", []):
            lv, buy, sell = {}, 0.0, 0.0
            for t_, a, bd in b.get("levels", []):
                lv[round(t_ * tick, 6)] = (float(a), float(bd))
                buy += float(a); sell += float(bd)
            out.append({"ts": int(b["t"]), "o": float(b["o"]), "h": float(b["h"]),
                        "l": float(b["l"]), "c": float(b["c"]), "v": float(b["v"]),
                        "d": float(b.get("d", buy - sell)),
                        "md": float(b.get("md", 0.0)),
                        "xd": float(b.get("xd", 0.0)),
                        "buy": buy, "sell": sell, "lv": lv})
        out.sort(key=lambda x: x["ts"])
        return out, tick


# ── تحليل عميق عبر نموذج لغوي ──────────────────────────────────────────
def worth_analysis(bars, sig):
    """ترشيح قبل استدعاء النموذج: لا ننفق نداءً على وضع بلا دلالة."""
    if sig:
        return True
    w = bars[-WIN:]
    pr = profile(w)
    if not pr:
        return False
    px = w[-1]["c"]; r = rng(w)
    near = min(abs(px - pr["vah"]), abs(px - pr["val"])) <= r
    return near or abs(delta_ratio(w[-1])) >= 0.15


_HTF = {}      # ذاكرة الإطار الأعلى — نصف ساعة


def agg(bars, minutes):
    """تجميع شمعات 5 دقائق إلى إطار أعلى."""
    sec = minutes * 60
    out = {}
    for b in bars:
        k = b["ts"] - (b["ts"] % sec)
        g = out.get(k)
        if g is None:
            out[k] = {"ts": k, "o": b["o"], "h": b["h"], "l": b["l"],
                      "c": b["c"], "d": b["d"], "v": b["v"]}
        else:
            g["h"] = max(g["h"], b["h"]); g["l"] = min(g["l"], b["l"])
            g["c"] = b["c"]; g["d"] += b["d"]; g["v"] += b["v"]
    return [out[k] for k in sorted(out)]


def htf_context(inst, cfg, cd, now):
    """سياق الإطار الأعلى: مستويات اليوم والأمس والأسبوع، واتجاه 4 ساعات.

    نافذة القرار 3 ساعات تعمي النظام عن المستويات الكبرى، وهي أول ما يقرأه
    متداول حقيقي. نسحب 7 أيام ونجمّعها محلياً — بلا مصدر جديد.
    """
    c = _HTF.get(inst)
    if c and now - c["at"] < 1800:
        return c["txt"]
    try:
        if cfg["src"] == "cd":
            bars = cd.bars(minutes=7 * 24 * 60)
        else:
            bars = okx_bars(cfg["sym"], cfg["bucket"], limit=300)
        if len(bars) < 50:
            return None
        bk = cfg["bucket"]
        day = 86400
        today = now - (now % day)
        d_now = [b for b in bars if b["ts"] >= today]
        d_prev = [b for b in bars if today - day <= b["ts"] < today]
        wk = bars[-min(len(bars), 7 * 288):]
        h4 = agg(bars, 240)[-6:]
        rows = [f"  {datetime.fromtimestamp(b['ts'], RIY).strftime('%d/%m %H:%M')} "
                f"ع{_fmt(b['o'], bk)} ق{_fmt(b['h'], bk)} ن{_fmt(b['l'], bk)} "
                f"إ{_fmt(b['c'], bk)} دلتا {b['d']:+,.0f}" for b in h4]
        lines = ["الإطار الأعلى:"]
        if d_prev:
            lines.append(f"  أمس: قمة {_fmt(max(b['h'] for b in d_prev), bk)} · "
                         f"قاع {_fmt(min(b['l'] for b in d_prev), bk)}")
        if d_now:
            lines.append(f"  اليوم: قمة {_fmt(max(b['h'] for b in d_now), bk)} · "
                         f"قاع {_fmt(min(b['l'] for b in d_now), bk)} · "
                         f"صافي دلتا {sum(b['d'] for b in d_now):+,.0f}")
        if wk:
            lines.append(f"  الأسبوع: قمة {_fmt(max(b['h'] for b in wk), bk)} · "
                         f"قاع {_fmt(min(b['l'] for b in wk), bk)}")
        pr7 = profile(bars[-2016:]) if cfg["src"] == "cd" else None
        if pr7:
            lines.append(f"  بروفايل الأسبوع: VAL {_fmt(pr7['val'], bk)} · "
                         f"POC {_fmt(pr7['poc'], bk)} · VAH {_fmt(pr7['vah'], bk)}")
        lines.append("  آخر 6 شمعات 4 ساعات:")
        lines += rows
        txt = "\n".join(lines)
        _HTF[inst] = {"at": now, "txt": txt}
        return txt
    except Exception:
        return None


def hvn_lvn(w, n=4):
    """عقد الحجم المرتفع والمنخفض داخل النافذة."""
    tot = {}
    for b in w:
        for pz, (a, bd) in b["lv"].items():
            tot[pz] = tot.get(pz, 0.0) + a + bd
    if len(tot) < 5:
        return [], []
    avg = sum(tot.values()) / len(tot)
    hv = sorted((k for k in tot if tot[k] > 1.8 * avg), key=lambda k: -tot[k])[:n]
    lv = sorted((k for k in tot if tot[k] < 0.3 * avg))[:n]
    return hv, lv


def _dec(bucket):
    """عدد الكسور اللازم لعرض سعر بهذه الخانة بلا فقدان دقة."""
    d = 0
    x = float(bucket)
    while x < 1 and d < 6:
        x *= 10; d += 1
    return d


def _fmt(p, bucket):
    return f"{p:,.{_dec(bucket)}f}"


def footprint_text(b, bucket):
    """أقوى مستويات الشمعة: السعر · Ask · Bid · الاختلال."""
    if not b["lv"]:
        return "لا مستويات"
    rows = sorted(b["lv"].items(), key=lambda kv: -(kv[1][0] + kv[1][1]))[:8]
    out = []
    for pz, (a, bd) in sorted(rows, key=lambda kv: -kv[0]):
        tag = ""
        if bd > 0 and a >= 3 * bd:
            tag = " ⇧اختلال شراء"
        elif a > 0 and bd >= 3 * a:
            tag = " ⇩اختلال بيع"
        out.append(f"  {_fmt(pz, bucket)}  Ask {a:,.0f} · Bid {bd:,.0f}{tag}")
    return "\n".join(out)


def flow_flags(w, bucket):
    """إشارات تُقرأ من الفوتبرنت نفسه لا من الشموع."""
    b = w[-1]
    f = []
    rngb = b["h"] - b["l"]
    dr = delta_ratio(b)
    # امتصاص: ضغط دلتا قوي بلا تقدم سعري
    if abs(dr) >= 0.25 and rngb > 0:
        avg_r = rng(w)
        if avg_r > 0 and rngb < 0.5 * avg_r:
            f.append(f"امتصاص محتمل: دلتا {dr*100:+.0f}% ومدى الشمعة "
                     f"{rngb:.4g} أقل من نصف المتوسط {avg_r:.4g}")
    # مزاد غير مكتمل: حجم معتبر عند الطرف
    if b["lv"]:
        hi, lo = max(b["lv"]), min(b["lv"])
        vol = [a + x for a, x in b["lv"].values()]
        mx = max(vol) or 1
        at_hi = sum(b["lv"][hi]); at_lo = sum(b["lv"][lo])
        if at_hi >= 0.35 * mx:
            f.append(f"مزاد غير مكتمل عند القمة {_fmt(hi, bucket)}")
        if at_lo >= 0.35 * mx:
            f.append(f"مزاد غير مكتمل عند القاع {_fmt(lo, bucket)}")
    # تطرّف الدلتا داخل الشمعة
    if b.get("xd") or b.get("md"):
        f.append(f"الدلتا داخل الشمعة: أعلى {b.get('xd',0):+,.0f} · "
                 f"أدنى {b.get('md',0):+,.0f} · الإغلاق {b['d']:+,.0f}")
    # حبس: دلتا قوية وإغلاق معاكس
    if abs(dr) >= 0.20:
        up = b["c"] > b["o"]
        if (dr > 0 and not up) or (dr < 0 and up):
            f.append(f"حبس محتمل: دلتا {dr*100:+.0f}% وإغلاق معاكس")
    return f


def analyze(cfg, bars, sig, why, cd=None):
    """قراءة سياق من النموذج. يُرجع نصاً أو None.

    النموذج يشرح ولا يقرر: بوابة المخاطرة والقواعد في الكود، وأي اقتراح
    يخالفها يُتجاهل. هذا متعمّد — الانضباط هو ما أثبت الاختبار أنه الحافة.
    """
    if not GROQ_KEY:
        return None
    w = bars[-WIN:]
    pr = profile(w)
    rows = [f"{datetime.fromtimestamp(b['ts'], RIY).strftime('%H:%M')} "
            f"o{b['o']:.1f} h{b['h']:.1f} l{b['l']:.1f} c{b['c']:.1f} "
            f"د{delta_ratio(b)*100:+.0f}%" for b in w[-14:]]
    htf = htf_context(cfg.get("_inst", cfg["name"]), cfg, cd, int(time.time())) if cd or cfg["src"] == "okx" else None
    hv, lv = hvn_lvn(w)
    cum = sum(b["buy"] - b["sell"] for b in w)
    flags = flow_flags(w, cfg["bucket"])
    state = (f"الأداة: {cfg['name']}\n"
             f"السعر {w[-1]['c']:,.1f} · المدى {rng(w):,.2f}\n"
             f"البروفايل: VAL {pr['val']:,.1f} · POC {pr['poc']:,.1f} · VAH {pr['vah']:,.1f}\n"
             f"عقد حجم مرتفع: {', '.join(_fmt(x, cfg['bucket']) for x in hv) or '—'}\n"
             f"عقد حجم منخفض: {', '.join(_fmt(x, cfg['bucket']) for x in lv) or '—'}\n"
             f"صافي دلتا النافذة (3 ساعات): {cum:+,.0f}\n\n"
             + ((htf + "\n\n") if htf else "")
             + "فوتبرنت آخر شمعة — أقوى المستويات:\n"
             + footprint_text(w[-1], cfg["bucket"]) + "\n\n"
             + ("ملاحظات من التدفق:\n- " + "\n- ".join(flags) + "\n\n" if flags else "")
             + f"آخر 14 شمعة (5 دقائق):\n" + "\n".join(rows) + "\n\n"
             + (f"إشارة: {sig['side']} دخول {sig['entry']:,.1f} ستوب {sig['stop']:,.1f}"
                f" هدف {sig['targets'][0]:,.1f} R:R 1:{sig['rr']}"
                if sig else f"لا إشارة. السبب: {why}"))
    prompt = (
        "أنت محلل تدفق أوامر محترف. تحليلك مؤصَّل على: نظرية المزاد "
        "(Auction Market Theory) وبروفايل الحجم، وقراءة الفوتبرنت "
        "(امتصاص · اختلال · مزاد غير مكتمل · حبس)، وCRT/سحب السيولة.\n\n"
        "أجب بالعربية في ست نقاط مرقّمة، سطر أو سطران لكل نقطة:\n"
        "1) السياق الأعلى: موقع السعر من مستويات اليوم والأمس والأسبوع، "
        "واتجاه شمعات 4 ساعات. هل نحن في اتجاه أم في نطاق؟\n"
        "2) المزاد: السعر داخل نطاق القيمة أم خارجه؟ وهل المزاد يقبل "
        "السعر (حجم يتراكم) أم يرفضه (عودة سريعة)؟\n"
        "3) الفوتبرنت: ماذا تقول أحجام Ask وBid عند المستويات المعطاة؟ "
        "اذكر مستوى واحداً بالرقم وما يعنيه.\n"
        "4) CRT وسحب السيولة: هل جرى اختراق قمة أو قاع ثم عودة للداخل؟\n"
        "5) التعارضات: ما الذي يناقض القراءة؟ اذكره صراحة. إن لم يوجد "
        "تعارض فقل ذلك.\n"
        "6) الحكم: متماسك / حذر / متعارض — وما الشرط الذي يؤكده أو ينفيه.\n\n"
        "انضباط إلزامي:\n"
        "• لا توصِ بدخول ولا تذكر أهدافاً — القرار محكوم بقواعد ثابتة خارج نطاقك.\n"
        "• لا تذكر رقماً غير موجود في البيانات. لا تقدّر ولا تستنتج أسعاراً.\n"
        "• إن لم تكفِ البيانات لبند، اكتب «البيانات لا تكفي» وانتقل. "
        "قراءة ناقصة صادقة أنفع من قراءة كاملة مخترَعة.\n"
        "• «ملاحظات من التدفق» مُحتسَبة من الفوتبرنت الحقيقي — اعتمدها، "
        "ولا تدّعِ امتصاصاً أو حبساً لم يرد فيها.\n\n"
        + state
    )
    try:
        r = httpx.post("https://api.groq.com/openai/v1/chat/completions",
                       headers={"Authorization": f"Bearer {GROQ_KEY}"},
                       json={"model": GROQ_MODEL, "temperature": 0.3,
                             "max_tokens": 800,
                             "messages": [{"role": "user", "content": prompt}]},
                       timeout=30)
        if r.status_code != 200:
            return None
        return r.json()["choices"][0]["message"]["content"].strip()[:1800]
    except Exception:
        return None


# ── مصدر OKX للبتكوين ──────────────────────────────────────────────────
def okx_bars(inst_id, bucket=10.0, limit=120):
    """شمعات 5 دقائق + دلتا المشترين/البائعين من taker-volume.

    حدّ معرفي يجب ذكره: OKX لا تعطي فوتبرنت لكل مستوى سعر. الدلتا حقيقية
    لكل خمس دقائق، أما توزيعها على المستويات فتقريبي (متساوٍ على مدى
    الشمعة). فالبروفايل وVAH/VAL تقريبية، والامتصاص والاختلال لا معنى لهما
    هنا. لا ندّعي غير ذلك في التقارير.
    """
    h = httpx.Client(timeout=25, headers={"User-Agent": "tradesys/2.0"})
    c = h.get(f"{OKX}/market/candles",
              params={"instId": inst_id, "bar": "5m", "limit": limit}).json()
    t = h.get(f"{OKX}/rubik/stat/taker-volume",
              params={"ccy": inst_id.split("-")[0], "instType": "CONTRACTS",
                      "period": "5m", "limit": limit}).json()
    if c.get("code") not in ("0", 0) or t.get("code") not in ("0", 0):
        raise RuntimeError(f"OKX: {c.get('msg') or t.get('msg')}")
    taker = {int(r[0]) // 1000: (float(r[1]), float(r[2])) for r in t.get("data", [])}
    out = []
    for r in c.get("data", []):
        ts = int(r[0]) // 1000
        if len(r) > 8 and r[8] == "0":      # شمعة قيد التكوين — تُسقط
            continue
        if ts not in taker:
            continue
        sell, buy = taker[ts]
        o, hi, lo, cl = float(r[1]), float(r[2]), float(r[3]), float(r[4])
        b0 = math.floor(lo / bucket) * bucket
        b1 = math.floor(hi / bucket) * bucket
        n = int(round((b1 - b0) / bucket)) + 1
        lv = {round(b0 + i * bucket, 6): (buy / n, sell / n) for i in range(n)}
        out.append({"ts": ts, "o": o, "h": hi, "l": lo, "c": cl,
                    "v": buy + sell, "d": buy - sell,
                    "buy": buy, "sell": sell, "lv": lv})
    out.sort(key=lambda x: x["ts"])
    return out


# ── مقاييس ─────────────────────────────────────────────────────────────
def profile(bars, pct=0.70):
    tot = {}
    for b in bars:
        for p, (a, bd) in b["lv"].items():
            tot[p] = tot.get(p, 0.0) + a + bd
    if not tot:
        return None
    ks = sorted(tot); total = sum(tot.values())
    poc = max(tot, key=tot.get); i = ks.index(poc)
    lo = hi = i; acc = tot[poc]
    while acc < pct * total and (lo > 0 or hi < len(ks) - 1):
        up = tot[ks[hi + 1]] if hi < len(ks) - 1 else -1
        dn = tot[ks[lo - 1]] if lo > 0 else -1
        if up >= dn: hi += 1; acc += up
        else:        lo -= 1; acc += dn
    return {"poc": poc, "vah": ks[hi], "val": ks[lo]}


def rng(bars, n=8):
    """متوسط المدى بعد استبعاد الشاذ (> 3× الوسيط). لا تضييق للستوب أبداً."""
    rs = [b["h"] - b["l"] for b in bars[-n:] if b["h"] > b["l"]]
    if not rs:
        return 0.0
    rs.sort(); med = rs[len(rs) // 2]
    keep = [r for r in rs if r <= 3 * med] or rs
    return sum(keep) / len(keep)


def delta_ratio(b):
    return (b["buy"] - b["sell"]) / b["v"] if b["v"] else 0.0


def integrity(bars, now):
    bad = []
    if not bars:
        return ["لا شمعات"]
    age = now - (bars[-1]["ts"] + TF * 60)
    if age > MAX_AGE:
        bad.append(f"آخر شمعة قديمة ({int(age)}s)")
    n = 0
    for b in bars[-WIN:]:
        if abs(b["buy"] + b["sell"] - b["v"]) > 1e-6 or \
           abs(b["buy"] - b["sell"] - b["d"]) > 1e-6:
            n += 1
    if n:
        bad.append(f"فوتبرنت غير متسق في {n} شمعة")
    return bad


def is_open(cfg, now=None):
    return cme_open(now) if cfg["hours"] == "cme" else True


def cme_open(now=None):
    """جلسة CME الكاملة — آسيا ولندن ونيويورك، لا جزءاً منها.

    تفتح الأحد 17:00 شيكاغو وتغلق الجمعة 16:00، باستراحة صيانة يومية
    16:00–17:00. المرجع بتوقيت شيكاغو لا الرياض، فيتبع التوقيت الصيفي
    تلقائياً — الفارق عن الرياض يتحرك بين 8 و9 ساعات خلال السنة.
    """
    t = datetime.fromtimestamp(now or time.time(), CHI)
    wd, m = t.weekday(), t.hour * 60 + t.minute
    if 16 * 60 <= m < 17 * 60: return False      # استراحة الصيانة اليومية
    if wd == 4 and m >= 16 * 60: return False    # الجمعة بعد الإغلاق
    if wd == 5: return False                     # السبت
    if wd == 6 and m < 17 * 60: return False     # الأحد قبل الافتتاح
    return True


# الجلسات بتوقيت الرياض — سياق للقراءة، لا بوابة للدخول
SESSIONS = [(3, 11, "آسيا"), (11, 16, "لندن"), (16, 19, "تداخل لندن/نيويورك"),
            (19, 24, "نيويورك"), (0, 3, "نيويورك المتأخرة")]


def session_name(ts):
    h = datetime.fromtimestamp(ts, RIY).hour
    for a, b, n in SESSIONS:
        if a <= h < b:
            return n
    return "—"


def trade_day(ts, cfg=None):
    """يوم التداول يبدأ عند افتتاح لندن 08:00 بتوقيت لندن.

    ليس منتصف الليل: جلسة آسيا قبل لندن امتداد لليوم السابق في سلوك السعر،
    وفصلها عند منتصف ليل الرياض كان يقطع الحركة نصفين. المرجع بتوقيت لندن
    لا الرياض، فيتبع التوقيت الصيفي البريطاني تلقائياً.
    """
    return (datetime.fromtimestamp(ts, LON)
            - timedelta(hours=8)).strftime("%Y-%m-%d")


def day_ends_now(ts, cfg=None):
    """نافذة نهاية اليوم: الدقائق الخمس قبل افتتاح لندن."""
    t = datetime.fromtimestamp(ts, LON)
    return t.hour == 7 and t.minute >= 55


# ── المحرّك ────────────────────────────────────────────────────────────
def propose(bars):
    w = bars[-WIN:]
    if len(w) < 12:
        return None, "شمعات غير كافية"
    pr = profile(w)
    if not pr:
        return None, "لا بروفايل"
    r = rng(w)
    if r <= 0:
        return None, "مدى صفري"
    last = w[-1]; px = last["c"]; dr = delta_ratio(last)

    if px > pr["vah"] and dr >= DELTA_MIN:
        side, lvl = "buy", pr["vah"]
    elif px < pr["val"] and dr <= -DELTA_MIN:
        side, lvl = "sell", pr["val"]
    elif pr["val"] <= px <= pr["vah"]:
        return None, f"السعر {px:,.1f} داخل نطاق القيمة [{pr['val']:,.1f} – {pr['vah']:,.1f}]"
    else:
        b = "VAH" if px > pr["vah"] else "VAL"
        return None, f"كسر {b} لكن الدلتا {dr*100:+.1f}% أضعف من {DELTA_MIN*100:.0f}%"

    sg = 1 if side == "buy" else -1
    stop = lvl - sg * r                     # الستوب من التقلب، بلا تضييق
    tg = [round(lvl + sg * k * r, 1) for k in (2, 3, 4)]
    entry = lvl                             # ارتداد عند المستوى — لا مطاردة
    risk = abs(entry - stop)
    if risk <= 0:
        return None, "مخاطرة صفرية"
    rr = round(abs(tg[0] - entry) / risk, 2)
    if rr < RR_MIN:
        return None, f"R:R 1:{rr} أقل من 1:{RR_MIN:.0f}"
    return {"side": side, "entry": round(entry, 1), "stop": round(stop, 1),
            "targets": tg, "rr": rr, "risk": round(risk, 1), "level": lvl,
            "delta": dr, "range": round(r, 2), "price": px,
            "poc": pr["poc"], "vah": pr["vah"], "val": pr["val"]}, None


# ── السجل وقواعد المخاطرة ──────────────────────────────────────────────
def db():
    os.makedirs(os.path.dirname(DB), exist_ok=True)
    c = sqlite3.connect(DB)
    c.execute("""CREATE TABLE IF NOT EXISTS sig(
        id INTEGER PRIMARY KEY, ts INT, day TEXT, inst TEXT, side TEXT, entry REAL,
        stop REAL, t1 REAL, t2 REAL, t3 REAL, rr REAL, status TEXT, r REAL)""")
    # أرشيف الشمعات — OKX لا تعطي تاريخ الدلتا، فنبنيه بأنفسنا.
    c.execute("""CREATE TABLE IF NOT EXISTS bar(
        inst TEXT, ts INT, o REAL, h REAL, l REAL, c REAL,
        v REAL, d REAL, PRIMARY KEY(inst, ts))""")
    # ترحيل: قواعد أُنشئت قبل إضافة البتكوين تفتقد عمود inst.
    cols = {r[1] for r in c.execute("PRAGMA table_info(sig)")}
    if "delta" not in cols:
        c.execute("ALTER TABLE sig ADD COLUMN delta REAL")
    if "inst" not in cols:
        c.execute("ALTER TABLE sig ADD COLUMN inst TEXT")
        c.execute("UPDATE sig SET inst='GC' WHERE inst IS NULL")
    # ترحيل حدّ اليوم إلى افتتاح لندن: الصفوف القديمة كُتبت بحدّ منتصف
    # الليل، فتُعاد تسميتها من طابعها الزمني. عملية متكررة بلا أثر جانبي،
    # ولا تمسّ أي نتيجة — الحدّ فقط هو ما تغيّر.
    fix = [(trade_day(t), i) for i, t in
           c.execute("SELECT id,ts FROM sig").fetchall()]
    c.executemany("UPDATE sig SET day=? WHERE id=? AND day<>?",
                  [(d, i, d) for d, i in fix])
    c.commit()
    return c


def day_str(ts):
    return datetime.fromtimestamp(ts, RIY).strftime("%Y-%m-%d")


def ledger(c, ts, inst, cfg=None):
    cfg = cfg or INSTRUMENTS[inst]
    d = trade_day(ts)
    rows = c.execute("SELECT status,r,entry,stop FROM sig "
                     "WHERE day=? AND inst=? ORDER BY ts", (d, inst)).fetchall()
    sent = len(rows)
    done = [x for x in rows if x[0] in ("target", "stop")]
    rr = sum(x[1] or 0 for x in done)
    # النقاط التراكمية: R مضروبة في مسافة المخاطرة تعطي حركة السعر الفعلية،
    # مقسومة على قيمة النقطة. هكذا يُقاس الهدف بالنقاط لا بالـ R وحدها.
    tick = cfg.get("tick") or 0.1
    pts = sum((x[1] or 0) * abs((x[2] or 0) - (x[3] or 0)) for x in done) / tick
    cs = 0
    for s, r, _e, _s in done:
        cs = cs + 1 if (r or 0) < 0 else 0
    # الصفقة القائمة تُقاس بلا قيد يوم: صفقة فُتحت قبل دوران اليوم
    # ما زالت قائمة، ولو قيّدناها باليوم لسمحنا بالتكديس فوقها.
    openp = c.execute("SELECT 1 FROM sig WHERE inst=? AND "
                      "status IN ('pending','active') LIMIT 1",
                      (inst,)).fetchone() is not None
    return {"sent": sent, "r": rr, "pts": pts, "consec": cs,
            "open": openp, "day": d}


def risk_block(l, mx, cfg=None):
    cfg = cfg or {}
    rt = cfg.get("rtarget", DAY_TARGET)
    pt = cfg.get("pts", 0)
    if l["open"]:       return "صفقة قائمة — لا تكديس"
    if l["sent"] >= mx: return f"بلغنا {mx} صفقات اليوم"
    if l["r"] <= LOSS_CAP:   return f"سقف الخسارة اليومي {LOSS_CAP}R"
    if l["r"] >= rt:    return f"تحقق هدف اليوم +{rt}R"
    if pt and l.get("pts", 0) >= pt:
        return f"تحقق هدف اليوم {pt} نقطة ({l['pts']:.0f})"
    if l["consec"] >= MAX_CONSEC: return "خسارتان متتاليتان — توقف"
    return None


def archive(c, inst, bars):
    """يحفظ الشمعات المسحوبة. مصدر الذهب يعطي تاريخه، أما البتكوين فلا —
    فهذا الأرشيف هو السبيل الوحيد لاختباره خلفياً لاحقاً."""
    try:
        c.executemany(
            "INSERT OR IGNORE INTO bar(inst,ts,o,h,l,c,v,d) VALUES(?,?,?,?,?,?,?,?)",
            [(inst, b["ts"], b["o"], b["h"], b["l"], b["c"], b["v"], b["d"])
             for b in bars])
        c.commit()
    except Exception:
        pass


def update(c, inst, bars):
    rows = c.execute("SELECT id,ts,side,entry,stop,t1,status FROM sig "
                     "WHERE inst=? AND status IN ('pending','active')",
                     (inst,)).fetchall()
    for sid, ts, side, entry, stop, t1, st in rows:
        nb = [b for b in bars if b["ts"] > ts]
        for b in nb:
            if st == "pending":
                if b["l"] <= entry <= b["h"]:
                    st = "active"
                    c.execute("UPDATE sig SET status='active' WHERE id=?", (sid,))
                elif b["ts"] - ts > 12 * TF * 60:
                    c.execute("UPDATE sig SET status='not_filled',r=0 WHERE id=?", (sid,))
                    break
                else:
                    continue
            hs = b["l"] <= stop if side == "buy" else b["h"] >= stop
            ht = b["h"] >= t1 if side == "buy" else b["l"] <= t1
            if hs:      # الستوب يفوز عند الالتباس داخل الشمعة
                c.execute("UPDATE sig SET status='stop',r=-1 WHERE id=?", (sid,)); break
            if ht:
                r = round(abs(t1 - entry) / abs(entry - stop), 2)
                c.execute("UPDATE sig SET status='target',r=? WHERE id=?", (r, sid)); break
    c.commit()


# ── النصوص ─────────────────────────────────────────────────────────────
def now_riy(ts):
    return datetime.fromtimestamp(ts, RIY).strftime("%H:%M")


def sig_text(s, l, ts, cfg):
    ar = "شراء" if s["side"] == "buy" else "بيع"
    return (f"🟢 إشارة {ar} — {cfg['name']}\n"
            f"{now_riy(ts)} الرياض · جلسة {session_name(ts)}\n\n"
            f"الدخول: {s['entry']:,.1f} (ارتداد على المستوى المكسور)\n"
            f"الستوب: {s['stop']:,.1f}  ({s['risk']} نقطة)\n"
            f"الأهداف: {s['targets'][0]:,.1f} · {s['targets'][1]:,.1f} · {s['targets'][2]:,.1f}\n"
            f"R:R للهدف الأول 1:{s['rr']}\n\n"
            f"السبب: كسر {'VAH' if s['side']=='buy' else 'VAL'} {s['level']:,.1f} "
            f"بإغلاق، دلتا {s['delta']*100:+.1f}%\n"
            f"البروفايل: VAL {s['val']:,.1f} · POC {s['poc']:,.1f} · VAH {s['vah']:,.1f}\n"
            f"المدى (8 شمعات): {s['range']}\n\n"
            f"يوم {l['day']}: {l['sent']+1}/{cfg['max']} · المحقق {l['r']:+.2f}R"
            + (f" · {l['pts']:+.0f} نقطة" if cfg.get('pts') else "") + "\n"
            f"الستوب إلزامي. النظام لا ينفّذ — القرار لك.")


def hour_text(ctx, why, l, bad, ts, cfg):
    x = [f"تقرير الساعة — {cfg['name']}",
         f"{now_riy(ts)} الرياض · جلسة {session_name(ts)}", ""]
    if ctx:
        x += [f"السعر: {ctx['price']:,.1f}",
              f"الدلتا: {ctx['delta']*100:+.1f}%",
              f"المدى: {ctx['range']}",
              f"POC {ctx['poc']:,.1f} | VAH {ctx['vah']:,.1f} | VAL {ctx['val']:,.1f}"]
    x += ["", f"لا صفقة: {why}"]
    x += ["سلامة البيانات: " + ("سليمة" if not bad else " / ".join(bad))]
    x += ["", f"يوم {l['day']}: {l['sent']}/{cfg['max']} صفقات · "
          f"المحقق {l['r']:+.2f}R" + (f" · {l['pts']:+.0f} نقطة" if cfg.get('pts') else "")]
    x += ["ملاحظة: لا سعر مرجعي مستقل — التحقق داخلي فقط" if cfg["src"] == "cd"
          else "ملاحظة: دلتا OKX حقيقية لكل 5 دقائق، وتوزيعها على المستويات تقريبي",
          news_line()]
    return "\n".join(x)


# ── الحلقة ─────────────────────────────────────────────────────────────
_NEWS_CACHE = {"ts": 0, "events": []}

def news_block(ts, before_min=30, after_min=20):
    """يمنع الإشارات حول أخبار USD عالية التأثير."""
    try:
        if ts - _NEWS_CACHE["ts"] > 21600:
            r = httpx.get("https://nfs.faireconomy.media/ff_calendar_thisweek.json", timeout=10)
            if r.status_code == 200:
                evs = []
                for e in r.json():
                    if e.get("country") == "USD" and e.get("impact") == "High":
                        dt = datetime.fromisoformat(e["date"])
                        evs.append((int(dt.timestamp()), e.get("title", "خبر USD")))
                _NEWS_CACHE["events"] = evs
                _NEWS_CACHE["ts"] = ts
        for ev_ts, title in _NEWS_CACHE["events"]:
            if -before_min * 60 <= (ts - ev_ts) <= after_min * 60:
                t_str = datetime.fromtimestamp(ev_ts, RIY).strftime("%H:%M")
                return f"فلتر الأخبار: {title} ({t_str} الرياض)"
    except Exception:
        _NEWS_CACHE["ok"] = False
        return None
    _NEWS_CACHE["ok"] = True
    return None


def news_line():
    """حالة الفلتر في التقرير — لا يدّعي حماية غير قائمة."""
    if not _NEWS_CACHE.get("events") and not _NEWS_CACHE.get("ok"):
        return "فلتر الأخبار: التغذية لا تستجيب — لا حماية الآن"
    n = len(_NEWS_CACHE.get("events") or [])
    return f"فلتر الأخبار: يعمل · {n} خبر USD عالي التأثير هذا الأسبوع"


def scan(c, cd, ts, inst, cfg):
    if not is_open(cfg, ts):
        return False, None, "السوق مغلق", []
    if cfg["src"] == "cd":
        cd.ensure()
        bars, _ = cd.bars()
    else:
        bars = okx_bars(cfg["sym"], cfg["bucket"])
    cfg["_bars"] = bars
    archive(c, inst, bars)
    update(c, inst, bars)
    bad = integrity(bars, ts)
    if bad:
        return False, None, "، ".join(bad), bad
    l = ledger(c, ts, inst, cfg)
    blk = risk_block(l, cfg["max"], cfg) or news_block(ts)
    s, why = propose(bars)
    ctx = s
    if not s:
        w = bars[-WIN:]
        pr = profile(w)
        if pr:
            ctx = {"price": w[-1]["c"], "delta": delta_ratio(w[-1]),
                   "range": round(rng(w), 2), **pr}
        return False, ctx, why, bad
    if blk:
        return False, ctx, blk, bad
    c.execute("INSERT INTO sig(ts,day,inst,side,entry,stop,t1,t2,t3,rr,delta,"
              "status,r) VALUES(?,?,?,?,?,?,?,?,?,?,?, 'pending', 0)",
              (ts, trade_day(ts, cfg), inst, s["side"], s["entry"], s["stop"],
               s["targets"][0], s["targets"][1], s["targets"][2], s["rr"],
               s["delta"]))
    c.commit()
    msg = sig_text(s, l, ts, cfg)
    a = analyze(cfg, bars, s, None, cd)
    if a:
        msg += "\n\n🧠 قراءة التدفق:\n" + a
    say(msg)
    return True, ctx, None, bad


# نطاقات قيد المراقبة — تُقاس ولا تُطبَّق. القرار بعد 30-50 صفقة حقيقية.
SHADOW = {
    "استبعاد 22–25%":        [(0.18, 0.22), (0.25, 1.10)],
    "استبعاد 22–30%":        [(0.18, 0.22), (0.30, 1.10)],
    "18–22% فقط":            [(0.18, 0.22)],
}


def shadow_text(c, inst=None):
    """يقارن أداء النظام الفعلي بما كانت ستعطيه النطاقات — بلا تطبيق.

    هذا تحقق أمامي نظيف: البيانات لم يرها أحد عند وضع القاعدة، فلا تداخل
    عيّنات ولا تطويع. القاعدة لا تُفعَّل إلا إن تفوّقت هنا.
    """
    q = "SELECT inst,delta,r,status FROM sig WHERE status IN ('stop','target')"
    rows = [r for r in c.execute(q) if r[1] is not None]
    if inst:
        rows = [r for r in rows if r[0] == inst]
    out = ["🔬 وضع الظل — مقارنة قواعد قيد المراقبة", ""]
    if len(rows) < 5:
        out.append(f"العيّنة {len(rows)} صفقة — صغيرة جداً. "
                   "نحتاج 30 على الأقل قبل أي حكم.")
        return "\n".join(out)

    def m(sub):
        if not sub:
            return "— لا صفقات"
        rs = [x[2] or 0 for x in sub]
        peak = run = dd = 0.0
        for r in rs:
            run += r; peak = max(peak, run); dd = max(dd, peak - run)
        w = sum(1 for r in rs if r > 0) / len(rs)
        return (f"n={len(rs):3d} · نجاح {w*100:4.1f}% · ناتج "
                f"{sum(rs)/len(rs):+.3f}R · محصلة {sum(rs):+6.1f}R · تراجع {dd:4.1f}R")

    out.append(f"المطبَّق الآن:        {m(rows)}")
    for name, bands in SHADOW.items():
        sub = [x for x in rows
               if any(lo <= abs(x[1]) < hi for lo, hi in bands)]
        out.append(f"{name:18}  {m(sub)}")
    out += ["", "لا تُفعَّل قاعدة حتى تتفوّق على المطبَّق في الناتج "
            "والتراجع معاً، وعلى 30 صفقة فأكثر."]
    return "\n".join(out)


def eod_text(c, ts, inst, cfg):
    """تقرير يوم أداة واحدة، عند نهاية يومها هي لا نهاية يوم غيرها."""
    day = trade_day(ts)
    led = ledger(c, ts, inst, cfg)
    rows = c.execute("SELECT status, r FROM sig WHERE day=? AND inst=?",
                     (day, inst)).fetchall()
    n = len(rows)
    r_sum = sum(x[1] or 0 for x in rows)
    wins = sum(1 for x in rows if (x[1] or 0) > 0)
    losses = sum(1 for x in rows if (x[1] or 0) < 0)
    pend = sum(1 for x in rows if x[0] in ("pending", "active"))
    nf = sum(1 for x in rows if x[0] == "not_filled")
    lines = [f"📊 نهاية اليوم — {cfg['name']}",
             f"{day} · من افتتاح لندن إلى افتتاح لندن", ""]
    if not n:
        lines.append("لا إشارات اليوم — الالتزام بالقواعد لا تقصير.")
    else:
        lines += [f"الإشارات: {n}/{cfg['max']}",
                  f"ربح {wins} · خسارة {losses}"
                  + (f" · لم تُنفَّذ {nf}" if nf else "")
                  + (f" · ما زالت قائمة {pend}" if pend else ""),
                  f"الصافي: {r_sum:+.2f}R"
                  + (f" · {led['pts']:+.0f} نقطة من {cfg['pts']}"
                     if cfg.get("pts") else "")]
    lines += ["", "العدادات صُفِّرت — يوم جديد يبدأ مع افتتاح لندن."]
    return "\n".join(lines)

def main():
    c = db(); cd = CD()
    say("✅ المحرّك يعمل — الذهب والبتكوين. فحص كل 5 دقائق، تقرير كل ساعة.\n"
        "الذهب: جلسة CME كاملة (آسيا ولندن ونيويورك) — الاثنين 02:00 حتى "
        "السبت 01:00 الرياض، باستراحة يومية ساعة عند 01:00.\n"
        "اليوم يدور: الذهب عند إغلاق الجلسة، والبتكوين عند منتصف ليل الرياض. "
        "عند الدوران تُصفَّر العدادات ويُرسل تقرير اليوم.")
    last_scan = 0; last_hour = -1; last_eod = {}; last_shadow = ""
    sent = {k: False for k in INSTRUMENTS}
    state = {k: (None, "لم يبدأ الفحص", []) for k in INSTRUMENTS}
    last_bars = {}
    errs = {}
    while True:
        try:
            ts = int(time.time()); hr = ts // 3600
            if ts - last_scan >= SCAN:
                last_scan = ts - (ts % SCAN)
                for inst, cfg in INSTRUMENTS.items():
                    try:
                        cfg["_inst"] = inst
                        ok, ctx, why, bad = scan(c, cd, ts, inst, cfg)
                        if cfg.get("_bars") is not None:
                            last_bars[inst] = cfg.pop("_bars")
                        state[inst] = (ctx, why, bad)
                        if ok:
                            sent[inst] = True
                    except Exception as e:
                        k = f"{inst}:{type(e).__name__}:{e}"[:160]
                        if errs.get(k, 0) < ts - 3600:
                            errs[k] = ts
                            if "ClusterDelta" in str(e):
                                say("⚠️ لا جلسة ClusterDelta — الذهب متوقف.\n"
                                    "sudo -u tradesys /opt/ts/venv/bin/python "
                                    "/opt/ts/tradesys.py register")
                            else:
                                say(f"خطأ في {cfg['name']}:\n"
                                    + traceback.format_exc()[-400:])
            if hr != last_hour and ts % 3600 < 120:
                if last_hour != -1:
                    for inst, cfg in INSTRUMENTS.items():
                        if sent[inst]:
                            continue
                        ctx, why, bad = state[inst]
                        msg = hour_text(ctx, why or "—", ledger(c, ts, inst, cfg),
                                        bad, ts, cfg)
                        bl = last_bars.get(inst)
                        if bl and worth_analysis(bl, None):
                            a = analyze(cfg, bl, None, why, cd)
                            if a:
                                msg += "\n\n🧠 قراءة التدفق:\n" + a
                        say(msg)
                last_hour = hr
                sent = {k: False for k in INSTRUMENTS}
            # اليوم يُقفل قبيل افتتاح لندن: رسالة لكل أداة.
            # يوم بلا إشارات والسوق مغلق (عطلة نهاية الأسبوع) لا يستحق رسالة.
            if day_ends_now(ts):
                d = trade_day(ts)
                for inst, cfg in INSTRUMENTS.items():
                    if last_eod.get(inst) == d:
                        continue
                    led = ledger(c, ts, inst, cfg)
                    if led["sent"] or is_open(cfg, ts):
                        say(eod_text(c, ts, inst, cfg))
                    last_eod[inst] = d
            # الظل يُرسل أسبوعياً فقط — لا قيمة لمقارنته يومياً
            wk_s = datetime.fromtimestamp(ts, RIY).strftime("%G-W%V")
            if day_ends_now(ts) and \
                    datetime.fromtimestamp(ts, LON).weekday() == 5 and \
                    last_shadow != wk_s:
                say(shadow_text(c))
                last_shadow = wk_s
        except Exception:
            try:
                say("خطأ عام:\n" + traceback.format_exc()[-400:])
            except Exception:
                pass
        time.sleep(30)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "check":
        # رسالة منفصلة لكل أداة — لا تُخلط القراءتان.
        c = db(); cd = CD(); ts = int(time.time())
        for inst, cfg in INSTRUMENTS.items():
            cfg["_inst"] = inst
            x = [f"🔎 فحص فوري — {cfg['name']}",
                 f"{now_riy(ts)} الرياض · جلسة {session_name(ts)}", ""]
            try:
                if not is_open(cfg, ts):
                    x.append("السوق مغلق")
                else:
                    bars = cd.bars() if cfg["src"] == "cd" else okx_bars(
                        cfg["sym"], cfg["bucket"])
                    if cfg["src"] == "cd":
                        bars = bars[0] if isinstance(bars, tuple) else bars
                    bad = integrity(bars, ts)
                    sig, why = propose(bars)
                    w = bars[-WIN:]; pr = profile(w)
                    led = ledger(c, ts, inst, cfg)
                    blk = risk_block(led, cfg["max"], cfg) or news_block(ts)
                    x += [f"{len(bars)} شمعة",
                          f"السعر {w[-1]['c']:,.1f} · دلتا "
                          f"{delta_ratio(w[-1])*100:+.1f}% · مدى {rng(w):,.2f}",
                          f"VAL {pr['val']:,.1f} · POC {pr['poc']:,.1f} · "
                          f"VAH {pr['vah']:,.1f}",
                          f"سلامة: {'سليمة' if not bad else ' / '.join(bad)}",
                          "القرار: " + (
                              f"إشارة {sig['side']} دخول {sig['entry']:,.1f} "
                              f"ستوب {sig['stop']:,.1f} R:R 1:{sig['rr']}"
                              if sig and not blk else (blk or why)),
                          f"يوم {led['day']}: {led['sent']}/{cfg['max']} · {led['r']:+.2f}R"
                          + (f" · {led['pts']:+.0f} نقطة" if cfg.get('pts') else ""),
                          news_line()]
                    a = analyze(cfg, bars, sig if not blk else None, blk or why, cd)
                    if a:
                        x += ["", "🧠 قراءة التدفق:", a]
            except Exception as e:
                x.append(f"خطأ — {type(e).__name__}: {e}"[:250])
            say("\n".join(x))
            print(cfg["name"], "— أُرسلت")
    elif len(sys.argv) > 1 and sys.argv[1] == "register":
        import getpass
        cd = CD()
        st = cd.status()
        if st.get("login"):
            print("الجلسة قائمة:", st["login"], "— تنتهي", st.get("expiration")); sys.exit(0)
        if cd.resume():
            print("أُحييت الجلسة بالمفتاح المحفوظ."); sys.exit(0)
        o = cd.register(input("إيميل ClusterDelta: ").strip(), getpass.getpass("كلمة المرور: "))
        print("تم:", o.get("login"), "— الاشتراك ينتهي", o.get("expiration"))
        b, t = cd.bars()
        print(f"تحقق: {len(b)} شمعة، آخر إغلاق {b[-1]['c'] if b else '—'}")
        say("✅ تم تسجيل جهاز ClusterDelta — الذهب جاهز.")
    elif len(sys.argv) > 1 and sys.argv[1] == "shadow":
        c = db()
        txt = shadow_text(c, sys.argv[2] if len(sys.argv) > 2 else None)
        say(txt); print(txt)
    elif len(sys.argv) > 1 and sys.argv[1] == "eod":
        c = db(); txt = eod_text(c, int(time.time())); say(txt); print(txt)
    else:
        main()
