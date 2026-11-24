#!/usr/bin/env python3
"""اختبار خلفي يعمل على السيرفر بنفس كود القرار.

    python backtest.py GC 180     # الذهب، 180 يوماً
    python backtest.py BTC 30     # البتكوين، 30 يوماً

مبادئ مُلزمة:
  • **نفس كود المحرّك** — propose و profile و rng و risk_block من tradesys.
    أي نسخة مبسّطة تجعل النتيجة بلا معنى.
  • **لا نظر للمستقبل** — عند كل شمعة نمرّر نافذة WIN السابقة فقط، وهي
    نفس نافذة الإنتاج. تمرير كل التاريخ يبني البروفايل على أيام بدل ساعات.
  • **الستوب يفوز عند الالتباس** داخل الشمعة. الافتراض المعاكس يرفع
    النتيجة زوراً.
  • **الدخول يُشترط تحققه** — صفقة الارتداد لا تُحتسب إلا إذا عاد السعر
    للمستوى خلال مهلة.
  • **التكاليف تُحتسب** — فرق سعر وانزلاق وعمولة.
  • **تحقق زمني** — ضبط على الأقدم واختبار على الأحدث، لا العكس.
"""
import sys
import time
from datetime import datetime, timedelta, timezone

import tradesys as T

def _arg(name, default=None):
    """--name value"""
    if name in sys.argv:
        i = sys.argv.index(name)
        if i + 1 < len(sys.argv):
            return sys.argv[i + 1]
    return default


COST = float(_arg("--cost", "0.04"))        # R لكل صفقة
OFFSET = int(_arg("--offset", "0"))         # نبدأ السحب قبل اليوم بـ N يوماً
BANDS = _arg("--bands", "")                 # مثال: 18-22,30-110

# أدوات إضافية للتحقق المتقاطع — نفس عقود ClusterDelta.
# إن صمدت قاعدة على الذهب وعلى هذه، فهي ليست خاصية أداة واحدة.
EXTRA = {
    "ES":  {"src": "cd", "sym": "es",  "bucket": 0.25, "max": 4, "hours": "gold", "name": "ES"},
    "NQ":  {"src": "cd", "sym": "nq",  "bucket": 0.25, "max": 4, "hours": "gold", "name": "NQ"},
    "CL":  {"src": "cd", "sym": "cl",  "bucket": 0.01, "max": 4, "hours": "gold", "name": "CL"},
    "SI":  {"src": "cd", "sym": "si",  "bucket": 0.005, "max": 4, "hours": "gold", "name": "SI"},
    "MGC": {"src": "cd", "sym": "mgc", "bucket": 0.1, "max": 4, "hours": "gold", "name": "MGC"},
}


def cfg_for(inst):
    return T.INSTRUMENTS.get(inst) or EXTRA[inst]


def parse_bands(spec):
    """'18-22,30-110' -> [(0.18,0.22),(0.30,1.10)]"""
    out = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        a, _, b = part.partition("-")
        out.append((float(a) / 100, float(b) / 100))
    return out


def in_bands(d, bands):
    return any(lo <= abs(d) < hi for lo, hi in bands)
ENTRY_WINDOW = 12        # شمعات مهلة تحقق دخول الارتداد
MAX_HOLD = 96


def fetch(inst, days):
    """سحب التاريخ على دفعات — ClusterDelta تحدّ النافذة لا التاريخ.

    OFFSET يزيح نافذة السحب للخلف، فنحصل على فترة لم تُستخدم في أي ضبط
    سابق — وهذا شرط التحقق النظيف.
    """
    cfg = cfg_for(inst)
    if cfg["src"] == "okx":
        return okx_history(cfg["sym"], cfg["bucket"], days)
    cd = T.CD(); cd.ensure()
    out, step = {}, 25           # 25 يوماً لكل طلب (الحد ~30)
    now = int(time.time()) - OFFSET * 86400
    for off in range(0, days, step):
        to = now - off * 86400
        frm = to - step * 86400
        r = cd.h.get(f"{T.BASE}/footprint.php",
                     params={"symbol": cfg["sym"], "tf": T.TF,
                             "from": frm, "to": to})
        if r.status_code in (401, 403):
            cd.ensure()
            continue
        if r.status_code != 200:
            break
        j = r.json(); tick = j.get("tickSize") or 0
        if tick <= 0:
            break
        for b in j.get("bars", []):
            lv, buy, sell = {}, 0.0, 0.0
            for t_, a, bd in b.get("levels", []):
                lv[round(t_ * tick, 6)] = (float(a), float(bd))
                buy += float(a); sell += float(bd)
            out[int(b["t"])] = {"ts": int(b["t"]), "o": float(b["o"]),
                                "h": float(b["h"]), "l": float(b["l"]),
                                "c": float(b["c"]), "v": float(b["v"]),
                                "d": float(b.get("d", buy - sell)),
                                "buy": buy, "sell": sell, "lv": lv}
        print(f"  …{len(out)} شمعة", flush=True)
    return [out[k] for k in sorted(out)]


def okx_history(inst_id, bucket, days):
    """تاريخ OKX على دفعات.

    نقطة candles تعطي الأحدث فقط، والتاريخ في history-candles. و
    taker-volume محدودة بـ100 صف لكل طلب، فنسحبها بالتقسيم أيضاً.
    """
    h = T.httpx.Client(timeout=30, headers={"User-Agent": "tradesys/2.0"})
    ccy = inst_id.split("-")[0]
    end = int(time.time() * 1000) - OFFSET * 86400000
    cand, taker = {}, {}
    need = days * 288                       # شمعة كل 5 دقائق
    cur = end
    while len(cand) < need:
        r = h.get(f"https://www.okx.com/api/v5/market/history-candles",
                  params={"instId": inst_id, "bar": "5m", "after": cur,
                          "limit": 100}).json()
        d = r.get("data") or []
        if not d:
            break
        for row in d:
            cand[int(row[0])] = row
        cur = int(d[-1][0])
        if len(cand) % 1000 < 100:
            print(f"  …{len(cand)} شمعة", flush=True)
    cur = end
    while len(taker) < need:
        r = h.get("https://www.okx.com/api/v5/rubik/stat/taker-volume",
                  params={"ccy": ccy, "instType": "CONTRACTS", "period": "5m",
                          "end": cur, "limit": 100}).json()
        d = r.get("data") or []
        if not d:
            break
        for row in d:
            taker[int(row[0])] = (float(row[1]), float(row[2]))
        nxt = int(d[-1][0])
        if nxt >= cur:
            break
        cur = nxt
    out = []
    for ms in sorted(cand):
        if ms not in taker:
            continue
        row = cand[ms]
        sell, buy = taker[ms]
        o, hi, lo, cl = (float(row[i]) for i in (1, 2, 3, 4))
        b0 = T.math.floor(lo / bucket) * bucket
        b1 = T.math.floor(hi / bucket) * bucket
        n = int(round((b1 - b0) / bucket)) + 1
        lv = {round(b0 + i * bucket, 6): (buy / n, sell / n) for i in range(n)}
        out.append({"ts": ms // 1000, "o": o, "h": hi, "l": lo, "c": cl,
                    "v": buy + sell, "d": buy - sell, "buy": buy, "sell": sell,
                    "lv": lv})
    print(f"  شمعات مطابقة: {len(out)} (سعر {len(cand)} · دلتا {len(taker)})")
    return out


def verify(bars):
    """سلامة البيانات: المستويات تجمع للحجم و(شراء−بيع)=الدلتا."""
    bad = 0
    for b in bars:
        s = sum(a + x for a, x in b["lv"].values())
        if abs(s - b["v"]) > max(1e-6, b["v"] * 1e-9) or \
           abs(b["buy"] - b["sell"] - b["d"]) > max(1e-6, abs(b["d"]) * 1e-9):
            bad += 1
    return bad


def outcome(bars, i, sig, scale=False):
    """نتيجة الصفقة بوحدة R.

    scale=False: خروج كامل عند الهدف الأول (1:2).
    scale=True : ثلث عند كل هدف (1:2 · 1:3 · 1:4) ونقل الستوب للتعادل
                 بعد الهدف الأول. هذا ما يفعله المتداول فعلياً.

    الستوب يفوز عند الالتباس داخل الشمعة في الحالتين.
    """
    entry, stop = sig["entry"], sig["stop"]
    t1, t2, t3 = sig["targets"]
    risk = abs(entry - stop)
    if risk <= 0:
        return None
    buy = sig["side"] == "buy"
    active = False
    cur_stop = stop
    got = 0                      # كم هدفاً تحقق
    r = 0.0
    for k in range(i + 1, min(i + 1 + MAX_HOLD, len(bars))):
        b = bars[k]
        if not active:
            if b["l"] <= entry <= b["h"]:
                active = True
            elif k - i > ENTRY_WINDOW:
                return {"st": "not_filled", "r": 0.0, "hit": 0}
            else:
                continue
        hs = b["l"] <= cur_stop if buy else b["h"] >= cur_stop
        if hs:                   # الستوب يفوز عند الالتباس
            left = 1.0 if not scale else (3 - got) / 3
            loss = (abs(cur_stop - entry) / risk) * (-1 if cur_stop == stop else 0)
            return {"st": "stop" if got == 0 else f"stop_after_t{got}",
                    "r": round(r + loss * left - COST, 3), "hit": got}
        if not scale:
            if (b["h"] >= t1) if buy else (b["l"] <= t1):
                return {"st": "target", "r": round(abs(t1 - entry) / risk - COST, 3),
                        "hit": 1}
            continue
        for n, t in ((1, t1), (2, t2), (3, t3)):
            if got >= n:
                continue
            if (b["h"] >= t) if buy else (b["l"] <= t):
                r += (abs(t - entry) / risk) / 3
                got = n
                if n == 1:
                    cur_stop = entry          # تعادل بعد الهدف الأول
        if got == 3:
            return {"st": "target3", "r": round(r - COST, 3), "hit": 3}
    # انتهت المهلة: نغلق الباقي عند إغلاق آخر شمعة
    if active and scale and got:
        last = bars[min(i + MAX_HOLD, len(bars) - 1)]["c"]
        left = (3 - got) / 3
        r += ((last - entry) / risk if buy else (entry - last) / risk) * left
        return {"st": f"expired_t{got}", "r": round(r - COST, 3), "hit": got}
    return {"st": "expired", "r": 0.0, "hit": got}


def stats(trades):
    f = [t for t in trades if t["st"] != "not_filled" and t["r"] != 0.0]
    if not f:
        return None
    rs = [t["r"] for t in f]
    peak = run = dd = 0.0
    streak = worst = 0
    for r in rs:
        run += r; peak = max(peak, run); dd = max(dd, peak - run)
        streak = streak + 1 if r < 0 else 0
        worst = max(worst, streak)
    return {"n": len(f), "not_filled": sum(1 for t in trades if t["st"] == "not_filled"),
            "win": round(sum(1 for r in rs if r > 0) / len(rs), 3),
            "exp": round(sum(rs) / len(rs), 3), "tot": round(sum(rs), 1),
            "dd": round(dd, 1), "streak": worst}


def run(bars, cfg, rules=True, bands=None, scale=False):
    """يُعيد قائمة الصفقات. rules=True يطبّق حدود المخاطرة اليومية."""
    trades = []
    day = None; dr = 0.0; n = 0; cs = 0; dp = 0.0
    tick = cfg.get("tick") or 0.1
    rt = cfg.get("rtarget", T.DAY_TARGET); ptgt = cfg.get("pts", 0)
    for i in range(T.WIN, len(bars) - 1):
        w = bars[max(0, i + 1 - T.WIN):i + 1]
        sig, _ = T.propose(w)
        if not sig:
            continue
        if bands and not in_bands(sig["delta"], bands):
            continue
        d = T.trade_day(bars[i]["ts"])
        if d != day:
            day, dr, n, cs, dp = d, 0.0, 0, 0, 0.0
        if rules and (n >= cfg["max"] or dr <= T.LOSS_CAP or dr >= rt
                      or (ptgt and dp >= ptgt) or cs >= T.MAX_CONSEC):
            continue
        o = outcome(bars, i, sig, scale=scale)
        if not o:
            continue
        n += 1
        if o["st"] in ("stop", "target"):
            dr += o["r"]
            dp += o["r"] * abs(sig["entry"] - sig["stop"]) / tick
            cs = cs + 1 if o["r"] < 0 else 0
        trades.append({**o, "ts": bars[i]["ts"], "side": sig["side"],
                       "rr": sig["rr"], "delta": sig["delta"],
                       "range": sig["range"]})
    return trades


def line(name, s):
    if not s:
        return f"  {name:22} — لا صفقات"
    return (f"  {name:22} n={s['n']:4d} نجاح {s['win']*100:5.1f}% "
            f"ناتج {s['exp']:+.3f}R محصلة {s['tot']:+7.1f}R "
            f"تراجع {s['dd']:5.1f}R أسوأ سلسلة {s['streak']}")


def main():
    inst = sys.argv[1] if len(sys.argv) > 1 else "GC"
    days = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].isdigit() else 90
    cfg = cfg_for(inst)
    bands = parse_bands(BANDS) if BANDS else None
    print(f"سحب {cfg['name']} — {days} يوماً…", flush=True)
    bars = fetch(inst, days)
    if len(bars) < T.WIN * 3:
        print(f"شمعات غير كافية: {len(bars)}"); return
    bad = verify(bars)
    f = lambda t: datetime.fromtimestamp(t, T.RIY).strftime("%Y-%m-%d")
    print(f"\n{len(bars)} شمعة · {f(bars[0]['ts'])} → {f(bars[-1]['ts'])} · "
          f"أخطاء سلامة: {bad}")
    if bad:
        print("تحذير: بيانات غير متسقة — النتيجة مشكوك فيها")

    print(f"\nالتكاليف {COST}R/صفقة · نافذة القرار {T.WIN} شمعة (نفس الإنتاج)"
          + (f" · إزاحة {OFFSET} يوماً" if OFFSET else "")
          + (f" · نطاقات {BANDS}" if bands else ""))
    print("\n=== الأساس ===")
    print(line("بلا قواعد مخاطرة", stats(run(bars, cfg, rules=False))))
    full = run(bars, cfg, rules=True)
    print(line("بقواعد المخاطرة", stats(full)))
    if bands:
        print(line(f"+ نطاقات {BANDS}", stats(run(bars, cfg, True, bands))))
    sc = run(bars, cfg, rules=True, bands=bands, scale=True)
    print("\n=== الخروج: كامل عند 1:2 مقابل تقسيم 1:2 · 1:3 · 1:4 ===")
    print(line("كامل عند الهدف الأول", stats(full)))
    print(line("ثلث عند كل هدف", stats(sc)))
    from collections import Counter
    cn = Counter(t["hit"] for t in sc if t["st"] not in ("not_filled",))
    tot = sum(cn.values()) or 1
    print(f"  بلوغ الأهداف: صفر {cn[0]*100//tot}% · "
          f"الأول {cn[1]*100//tot}% · الثاني {cn[2]*100//tot}% · "
          f"الثالث {cn[3]*100//tot}%")

    cut = bars[0]["ts"] + int((bars[-1]["ts"] - bars[0]["ts"]) * 0.67)
    print(f"\n=== تحقق زمني (ضبط حتى {f(cut)}) ===")
    print(line("ضبط", stats([t for t in full if t["ts"] < cut])))
    print(line("اختبار", stats([t for t in full if t["ts"] >= cut])))

    print("\n=== عزل: نطاق الدلتا ===")
    for lo, hi in ((0.18, 0.22), (0.22, 0.25), (0.25, 0.30), (0.30, 1.1)):
        sub = [t for t in full if lo <= abs(t["delta"]) < hi]
        print(line(f"{lo*100:.0f}–{hi*100:.0f}%", stats(sub)))

    print("\n=== عزل: الاتجاه ===")
    for s in ("buy", "sell"):
        print(line(s, stats([t for t in full if t["side"] == s])))

    print("\nتذكير: رقم الاختبار ليس وعداً. عيّنة الاختبار الصغيرة تكفي "
          "لرفض قاعدة لا لاعتمادها.")


if __name__ == "__main__":
    main()
