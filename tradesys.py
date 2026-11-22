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
    "GC": {"src": "cd", "sym": "gc", "bucket": 0.1, "max": 4,
           "hours": "gold", "name": "الذهب GC"},
    "BTC": {"src": "okx", "sym": "BTC-USDT-SWAP", "bucket": 10.0, "max": 5,
            "hours": "24/7", "name": "البتكوين"},
}
WIN    = 36                # نافذة القرار: 3 ساعات (نفس نافذة الاختبار)
DELTA_MIN   = 0.18         # بوابة الدلتا
RR_MIN      = 2.0
MAX_TRADES  = 4
LOSS_CAP    = -2.0
DAY_TARGET  = 3.0
MAX_CONSEC  = 2
MAX_AGE     = 900          # عمر آخر شمعة خمسية (ثانية)
SCAN        = 300
RIY = timezone(timedelta(hours=3))


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
            if r.status_code == 401:
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
        st = self.status()
        if st.get("login"):
            return st
        st = self.resume()
        if st and st.get("login"):
            return st
        raise RuntimeError("لا جلسة ClusterDelta — سجّل الجهاز")

    def bars(self, minutes=600):
        """المستويات [تكّات, Ask=شراء, Bid=بيع]؛ السعر = التكّات × tickSize."""
        to = int(time.time())
        r = self.h.get(f"{BASE}/footprint.php",
                       params={"symbol": SYMBOL, "tf": TF,
                               "from": to - minutes * 60, "to": to})
        if r.status_code == 401:
            self.ensure()
            r = self.h.get(f"{BASE}/footprint.php",
                           params={"symbol": SYMBOL, "tf": TF,
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
                        "buy": buy, "sell": sell, "lv": lv})
        out.sort(key=lambda x: x["ts"])
        return out, tick


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
    return gold_open(now) if cfg["hours"] == "gold" else True


def gold_open(now=None):
    t = datetime.fromtimestamp(now or time.time(), RIY)
    wd, h = t.weekday(), t.hour
    if wd == 6: return False
    if wd == 0 and h < 10: return False
    if wd == 5 and h >= 1: return False
    return True


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
    # ترحيل: قواعد أُنشئت قبل إضافة البتكوين تفتقد عمود inst.
    cols = {r[1] for r in c.execute("PRAGMA table_info(sig)")}
    if "inst" not in cols:
        c.execute("ALTER TABLE sig ADD COLUMN inst TEXT")
        c.execute("UPDATE sig SET inst='GC' WHERE inst IS NULL")
    c.commit()
    return c


def day_str(ts):
    return datetime.fromtimestamp(ts, RIY).strftime("%Y-%m-%d")


def ledger(c, ts, inst):
    d = day_str(ts)
    rows = c.execute("SELECT status,r FROM sig WHERE day=? AND inst=? ORDER BY ts",
                     (d, inst)).fetchall()
    sent = len(rows)
    done = [x for x in rows if x[0] in ("target", "stop")]
    rr = sum(x[1] or 0 for x in done)
    cs = 0
    for s, r in done:
        cs = cs + 1 if (r or 0) < 0 else 0
    openp = any(x[0] in ("pending", "active") for x in rows)
    return {"sent": sent, "r": rr, "consec": cs, "open": openp}


def risk_block(l, mx):
    if l["open"]:       return "صفقة قائمة — لا تكديس"
    if l["sent"] >= mx: return f"بلغنا {mx} صفقات اليوم"
    if l["r"] <= LOSS_CAP:   return f"سقف الخسارة اليومي {LOSS_CAP}R"
    if l["r"] >= DAY_TARGET: return f"تحقق هدف اليوم +{DAY_TARGET}R"
    if l["consec"] >= MAX_CONSEC: return "خسارتان متتاليتان — توقف"
    return None


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
    return (f"🟢 إشارة {ar} — {cfg['name']}\n{now_riy(ts)} الرياض\n\n"
            f"الدخول: {s['entry']:,.1f} (ارتداد على المستوى المكسور)\n"
            f"الستوب: {s['stop']:,.1f}  ({s['risk']} نقطة)\n"
            f"الأهداف: {s['targets'][0]:,.1f} · {s['targets'][1]:,.1f} · {s['targets'][2]:,.1f}\n"
            f"R:R للهدف الأول 1:{s['rr']}\n\n"
            f"السبب: كسر {'VAH' if s['side']=='buy' else 'VAL'} {s['level']:,.1f} "
            f"بإغلاق، دلتا {s['delta']*100:+.1f}%\n"
            f"البروفايل: VAL {s['val']:,.1f} · POC {s['poc']:,.1f} · VAH {s['vah']:,.1f}\n"
            f"المدى (8 شمعات): {s['range']}\n\n"
            f"اليوم: {l['sent']+1}/{cfg['max']} · المحقق {l['r']:+.2f}R\n"
            f"الستوب إلزامي. النظام لا ينفّذ — القرار لك.")


def hour_text(ctx, why, l, bad, ts, cfg):
    x = [f"تقرير الساعة — {cfg['name']}", f"{now_riy(ts)} الرياض", ""]
    if ctx:
        x += [f"السعر: {ctx['price']:,.1f}",
              f"الدلتا: {ctx['delta']*100:+.1f}%",
              f"المدى: {ctx['range']}",
              f"POC {ctx['poc']:,.1f} | VAH {ctx['vah']:,.1f} | VAL {ctx['val']:,.1f}"]
    x += ["", f"لا صفقة: {why}"]
    x += ["سلامة البيانات: " + ("سليمة" if not bad else " / ".join(bad))]
    x += ["", f"اليوم: {l['sent']}/{cfg['max']} صفقات · المحقق {l['r']:+.2f}R"]
    x += ["ملاحظة: لا سعر مرجعي مستقل — التحقق داخلي فقط" if cfg["src"] == "cd"
          else "ملاحظة: دلتا OKX حقيقية لكل 5 دقائق، وتوزيعها على المستويات تقريبي",
          "فلتر الأخبار: معطّل — لا تغذية أخبار مُعدّة"]
    return "\n".join(x)


# ── الحلقة ─────────────────────────────────────────────────────────────
def scan(c, cd, ts, inst, cfg):
    if not is_open(cfg, ts):
        return False, None, "السوق مغلق", []
    if cfg["src"] == "cd":
        cd.ensure()
        bars, _ = cd.bars()
    else:
        bars = okx_bars(cfg["sym"], cfg["bucket"])
    update(c, inst, bars)
    bad = integrity(bars, ts)
    if bad:
        return False, None, "، ".join(bad), bad
    l = ledger(c, ts, inst)
    blk = risk_block(l, cfg["max"])
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
    c.execute("INSERT INTO sig(ts,day,inst,side,entry,stop,t1,t2,t3,rr,status,r) "
              "VALUES(?,?,?,?,?,?,?,?,?,?, 'pending', 0)",
              (ts, day_str(ts), inst, s["side"], s["entry"], s["stop"],
               s["targets"][0], s["targets"][1], s["targets"][2], s["rr"]))
    c.commit()
    say(sig_text(s, l, ts, cfg))
    return True, ctx, None, bad


def main():
    c = db(); cd = CD()
    say("✅ المحرّك يعمل — الذهب والبتكوين. فحص كل 5 دقائق، تقرير كل ساعة.")
    last_scan = 0; last_hour = -1
    sent = {k: False for k in INSTRUMENTS}
    state = {k: (None, "لم يبدأ الفحص", []) for k in INSTRUMENTS}
    errs = {}
    while True:
        try:
            ts = int(time.time()); hr = ts // 3600
            if ts - last_scan >= SCAN:
                last_scan = ts - (ts % SCAN)
                for inst, cfg in INSTRUMENTS.items():
                    try:
                        ok, ctx, why, bad = scan(c, cd, ts, inst, cfg)
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
                        say(hour_text(ctx, why or "—", ledger(c, ts, inst),
                                      bad, ts, cfg))
                last_hour = hr
                sent = {k: False for k in INSTRUMENTS}
        except Exception:
            try:
                say("خطأ عام:\n" + traceback.format_exc()[-400:])
            except Exception:
                pass
        time.sleep(30)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "check":
        # فحص فوري لكل أداة: يطبع القرار الحيّ ويرسله للقناة.
        c = db(); cd = CD(); ts = int(time.time())
        lines = [f"🔎 فحص فوري — {now_riy(ts)} الرياض", ""]
        for inst, cfg in INSTRUMENTS.items():
            try:
                if not is_open(cfg, ts):
                    lines += [f"{cfg['name']}: السوق مغلق", ""]
                    print(cfg["name"], "— السوق مغلق"); continue
                bars = cd.bars()[0] if cfg["src"] == "cd" else okx_bars(cfg["sym"], cfg["bucket"])
                bad = integrity(bars, ts)
                sig, why = propose(bars)
                w = bars[-WIN:]; pr = profile(w)
                led = ledger(c, ts, inst)
                blk = risk_block(led, cfg["max"])
                lines += [f"{cfg['name']}  ({len(bars)} شمعة)",
                          f"  السعر {w[-1]['c']:,.1f} · دلتا {delta_ratio(w[-1])*100:+.1f}%"
                          f" · مدى {rng(w):,.2f}",
                          f"  VAL {pr['val']:,.1f} · POC {pr['poc']:,.1f} · VAH {pr['vah']:,.1f}",
                          f"  سلامة: {'سليمة' if not bad else ' / '.join(bad)}",
                          f"  القرار: " + (
                              f"إشارة {sig['side']} دخول {sig['entry']:,.1f} ستوب {sig['stop']:,.1f}"
                              f" R:R 1:{sig['rr']}" if sig else (blk or why)),
                          f"  اليوم: {led['sent']}/{cfg['max']} · {led['r']:+.2f}R", ""]
                print(lines[-6]); print(lines[-2])
            except Exception as e:
                lines += [f"{cfg['name']}: خطأ — {type(e).__name__}: {e}"[:200], ""]
                print(cfg["name"], "خطأ:", type(e).__name__, str(e)[:120])
        say("\n".join(lines))
        print("أُرسل للقناة.")
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
    else:
        main()
