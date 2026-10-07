---
name: "vuln-monthly-check"
description: "PHP・OpenJDK・Composer など、使用中のソフトウェア/モジュールのバージョンに脆弱性(CVE)があるかを月次で調査し、該当CVE番号を返す。「脆弱性チェック」「月次の脆弱性調査」「Java 21 にCVEある?」などで使用。"
---

# 月次脆弱性チェック (PHP / OpenJDK / Composer / その他)

対象のソフトウェアとバージョンについて、公式/一次情報源から
**そのバージョンに残っている CVE** と **集計期間 (既定: 前月) に新たに公表された CVE** を返す。

## 対応製品とデータソース

| product | 対象 | 情報源 | 「期間内」の判定日 |
|---|---|---|---|
| `php` | PHP本体 | php.net ChangeLog | 修正版のリリース日 |
| `openjdk` | OpenJDK (Temurin/Corretto等のOpenJDKビルドも可) | openjdk.org Vulnerability Advisories | アドバイザリ公開日 |
| `composer` | Composer本体 | Packagist Security Advisories API | 報告日 |
| `packagist` | 任意のComposerパッケージ (例 laravel/framework) | 同上 | 報告日 |
| `osv` | npm / PyPI / Maven / Go / RubyGems / crates.io / NuGet 等 | OSV.dev | 公開日 |
| `records` | 上記以外 (nginx, MySQL 等) | 手動で作るレコードJSON (後述) | 記載日 |

判定ロジック:
- **php**: 同一ブランチで対象より新しいリリースで修正された CVE = 残存。
- **openjdk**: 各四半期アドバイザリの「affected versions are …, and earlier」に対象が含まれ、かつリスク表の該当メジャー列に印がある CVE = 残存。アドバイザリは1/4/7/10月のみ公開のため、それ以外の月は新規0件が通常。
- **composer/packagist**: `affectedVersions` 制約に対象バージョンが含まれる = 残存。CVE 未採番のものは GHSA ID で返す。
- **osv**: OSV.dev がバージョン一致を判定。CVE エイリアスがあれば CVE 番号で返す。

## 手順

### 1. 対象とバージョンを確定する

ユーザー指定がなければ次の順で取得を試み、だめなら AskUserQuestion で聞く:
- PHP: `php -r 'echo PHP_VERSION;'`、`composer.json` の `config.platform.php`、Dockerfile `FROM php:x.y.z`
- Java: `java -version` (例 `21.0.4`, `1.8.0_452`, `8u452` いずれも可)、Dockerfile `FROM eclipse-temurin:21.0.4_7-jre`
- Composer: `composer --version`
- 他: `npm ls`, `pip show` 等

パッチ番号まで必要 (8.2 ではなく 8.2.10)。複数環境 (本番/ステージング等) があれば label を付けて全部チェックする。
対象が複数なら targets.json を作って `batch` で一括実行する。

### 2. スクリプトを実行する

末尾「付録: vuln_check.py」を作業ディレクトリ(スクラッチ領域)に `vuln_check.py` として保存して実行する。

```bash
python3 -I vuln_check.py php 8.2.10
python3 -I vuln_check.py php --detect                 # ローカルの php から自動検出
python3 -I vuln_check.py openjdk 21.0.4
python3 -I vuln_check.py composer 2.7.1
python3 -I vuln_check.py packagist laravel/framework 10.48.0
python3 -I vuln_check.py osv npm lodash 4.17.20
python3 -I vuln_check.py batch targets.json            # 一括
python3 -I vuln_check.py --json --since 2026-09-01 --until 2026-09-30 batch targets.json
```

targets.json の例:

```json
[
  {"product": "php", "version": "8.2.10", "label": "PHP(本番)"},
  {"product": "openjdk", "version": "21.0.4"},
  {"product": "composer", "version": "2.7.1"},
  {"product": "packagist", "package": "laravel/framework", "version": "10.48.0"},
  {"product": "osv", "ecosystem": "npm", "package": "lodash", "version": "4.17.20"},
  {"product": "records", "version": "1.24.0", "label": "nginx", "input": "nginx_records.json"}
]
```

ユーザーが毎月同じ対象を調べるなら、targets.json を接続フォルダに保存しておくことを提案する。

### 3. ネットワークで取得できない場合 (403 / proxy エラー等)

順に試す:
1. ユーザーのPCに接続されていれば、そちらのシェル (device_bash) でスクリプトを実行する。
2. WebFetch で情報源を取得し、`--input` で渡す:
   - php: `https://www.php.net/ChangeLog-{major}.php` から、対象より新しい各 "Version x.y.z" の版・日付・CVE行を**そのまま**抜き出し (要約させない。長いページは offset で続きを読む)、`### Version x.y.z` / `**DD Mon YYYY**` / `- … (CVE-…)` 形式で保存 → `php <ver> --input file.md`
   - composer/packagist: `https://packagist.org/api/security-advisories/?packages[]=<vendor/name>` の JSON を全項目そのまま保存 → `--input file.json`
   - openjdk/osv/その他: 下記 records JSON を作って `records` で実行する。
3. records JSON の形式 (どの製品でも使える):

```json
[{"id": "CVE-2026-30001", "date": "2026-07-21", "fixed_in": "21.0.11",
  "desc": "core-libs/java.net", "severity": "8.6", "ref": "https://..."},
 {"id": "CVE-2026-59944", "date": "2026-10-02", "affected": ">=2.3.0,<2.10.3"}]
```
`fixed_in` (これ未満が影響) か `affected` (Composer形式の制約) のどちらかを入れる。
OpenJDK なら各アドバイザリ `https://openjdk.org/groups/vulnerability/advisories/YYYY-MM-DD` の
「affected versions」と表の該当メジャー列から、`affected: "<=21.0.10"` のように作る。
その他製品 (nginx 等) はベンダーのセキュリティアドバイザリや NVD から作る。
実行: `python3 -I vuln_check.py records <製品名> <version> records.json`

### 4. EOL / サポート外の扱い

- PHP は endoflife.date で自動確認 (取得失敗時は `https://www.php.net/supported-versions.php` を WebFetch)。
- OpenJDK は最新アドバイザリに対象メジャーが無ければ警告が出る (非LTSの22/23/24など)。
- EOL の場合「⚠ サポート終了。EOL後の脆弱性は記載されないため結果は網羅的ではない」と明記し、アップグレードを推奨する。
- 参考として、サポート中の最古ブランチ/メジャーで対象期間に修正された CVE を「影響の可能性あり」として別枠で列挙する。

### 5. (任意) 深刻度の補足

ユーザーが求めた場合のみ、NVD (`https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=<CVE>`) の CVSS を添える。NVD 未登録 (Reserved) のものはその旨を書く。

## 出力形式

対象ごとに結論を先頭に、CVE 番号を必ず列挙する:

```
## 脆弱性チェック結果 (YYYY年M月分)

### PHP 8.2.10 (本番) — 脆弱性あり / 最新 8.2.12
今月の新規: CVE-2026-91768
| CVE | 公表日 | 深刻度 | 修正版 | 概要 |
|---|---|---|---|---|
| CVE-2026-91768 [NEW] | 2026-09-24 | - | 8.2.12 | FastCGI ACL バイパス |

### OpenJDK 21.0.4 — 脆弱性あり …
### Composer 2.10.3 — 該当 CVE なし

まとめ: 要対応 2件 (PHP→8.2.12, OpenJDK→2026-07 CPU 以降)
出典: 各 source URL
```

概要は日本語に短く訳す。CVE 番号・バージョンは推測で補わず、取得データにあるものだけを書く。
スクリプトがエラーを返した対象は「取得失敗」と明記し、手順3で再試行する。

## 付録: vuln_check.py

```python
#!/usr/bin/env python3
"""ソフトウェア/モジュールのバージョンに対する脆弱性(CVE)チェッカー (月次調査用)。

対応ソース:
  php       php.net ChangeLog                      例: php 8.2.10
  openjdk   OpenJDK Vulnerability Advisories       例: openjdk 21.0.4  (8u452 / 1.8.0_452 も可)
  composer  Composer本体 (Packagist API)           例: composer 2.7.1
  packagist 任意のComposerパッケージ (Packagist API) 例: packagist laravel/framework 10.0.0
  osv       OSV.dev (npm, PyPI, Maven, Go, RubyGems, crates.io, NuGet, Packagist ...)
                                                   例: osv npm lodash 4.17.20
  records   手動で作成したレコードJSON (ネット取得不可時/その他製品)
  batch     targets.json に列挙した複数対象を一括実行

共通オプション: --since/--until (既定: 前月1日〜前月末日), --json
取得済みデータを使う: --input (php/packagist/osv: ファイル, openjdk: ディレクトリ)
標準ライブラリのみ。
"""
import argparse
import datetime as dt
import html
import json
import os
import re
import subprocess
import sys
import urllib.parse
import urllib.request

UA = {"User-Agent": "vuln-check/2.0"}
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")
GHSA_RE = re.compile(r"GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}")
MONTHS = "Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec"


# ---------------------------------------------------------------- 共通
def fetch(url, data=None, timeout=30):
    req = urllib.request.Request(url, data=data, headers={**UA, **({"Content-Type": "application/json"} if data else {})})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")


def read_file(p):
    with open(p, encoding="utf-8", errors="replace") as f:
        return f.read()


def strip_tags(s):
    return re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", " ", s))).strip()


def vtuple(v):
    """汎用バージョン比較キー。数字列のみ使用 (プレリリース表記は無視)。"""
    v = str(v).strip().lstrip("vV")
    v = re.split(r"[-+ ]", v)[0]
    nums = [int(x) for x in re.findall(r"\d+", v)]
    return tuple(nums + [0] * (4 - len(nums))) if nums else (0,)


def java_tuple(v):
    """8u452 / 1.8.0_452 / 17.0.12+7 / 21 → (feature, interim, update)"""
    v = str(v).strip()
    m = re.match(r"^(?:1\.)?(\d+)(?:\.0)?[u_](\d+)", v)  # 8u452, 1.8.0_452
    if m:
        return (int(m.group(1)), 0, int(m.group(2)))
    m = re.match(r"^(\d+)(?:\.(\d+))?(?:\.(\d+))?", v)
    if not m:
        raise ValueError(f"Javaバージョン形式が不正: {v}")
    return tuple(int(x or 0) for x in m.groups())


def parse_date(s):
    if not s:
        return None
    s = str(s)
    m = re.search(r"(\d{4})[-/](\d{2})[-/](\d{2})", s)
    if m:
        return dt.date(*map(int, m.groups()))
    m = re.search(rf"\b(\d{{1,2}})\s+({MONTHS})[a-z]*\s+(\d{{4}})\b", s)
    if m:
        return dt.datetime.strptime(" ".join(m.groups()), "%d %b %Y").date()
    return None


def default_period():
    first_this = dt.date.today().replace(day=1)
    last_prev = first_this - dt.timedelta(days=1)
    return last_prev.replace(day=1), last_prev


def finding(id_, date=None, fixed_in=None, desc="", severity=None, ref=None, aliases=None):
    return {"id": id_, "aliases": aliases or [], "date": date.isoformat() if date else None,
            "fixed_in": fixed_in, "severity": severity, "desc": (desc or "")[:300], "ref": ref}


def match_constraint(version, constraint):
    """Composer形式の制約 '>=1.0,<2.2.30|>=2.3.0,<2.10.3' に version が含まれるか"""
    v = vtuple(version)
    for alt in re.split(r"\s*\|\|?\s*", constraint.strip()):
        ok = True
        for part in re.split(r"\s*,\s*|\s+", alt.strip()):
            if not part or part == "*":
                continue
            m = re.match(r"^(>=|<=|>|<|==|=|!=)?\s*(.+)$", part)
            op, ver = m.group(1) or "=", vtuple(m.group(2))
            ok = {"<": v < ver, "<=": v <= ver, ">": v > ver, ">=": v >= ver,
                  "=": v == ver, "==": v == ver, "!=": v != ver}[op]
            if not ok:
                break
        if ok:
            return True
    return False


# ---------------------------------------------------------------- PHP
PHP_HEAD = re.compile(r"(?:<h[1-4][^>]*>\s*|^#{1,4}\s*)Version\s+(\d+\.\d+\.\d+)", re.M)


def check_php(version, inp=None, **_):
    cur = vtuple(version)[:3]
    text = read_file(inp) if inp else fetch(f"https://www.php.net/ChangeLog-{cur[0]}.php")
    heads = list(PHP_HEAD.finditer(text))
    releases = {}
    for i, h in enumerate(heads):
        ver = h.group(1)
        body = text[h.end(): heads[i + 1].start() if i + 1 < len(heads) else len(text)]
        m = re.search(r"datetime=['\"](\d{4}-\d{2}-\d{2})", body[:600])
        date = parse_date(m.group(1)) if m else parse_date(body[:600])
        units = re.findall(r"<li>(.*?)</li>", body, re.S) or body.splitlines()
        items = []
        for u in units:
            for c in dict.fromkeys(CVE_RE.findall(u)):
                g = GHSA_RE.search(u)
                items.append((c, g.group(0) if g else None, re.sub(r"\]\([^)]*\)", "]", strip_tags(u))))
        releases.setdefault(ver, (date, items))
    branch = {v: d for v, d in releases.items() if vtuple(v)[:2] == cur[:2]}
    if not branch:
        raise RuntimeError(f"ChangeLog にブランチ {cur[0]}.{cur[1]} が見つかりません")
    out = []
    for v in sorted(branch, key=vtuple):
        if vtuple(v)[:3] <= cur:
            continue
        date, items = branch[v]
        for c, g, d in items:
            out.append(finding(c, date, v, d, aliases=[g] if g else [], ref=f"https://www.php.net/ChangeLog-{cur[0]}.php#{v}"))
    latest = max(branch, key=vtuple)
    notes = []
    eol = endoflife("php", f"{cur[0]}.{cur[1]}")
    if eol:
        notes.append(eol)
    return {"latest": latest, "findings": out, "notes": notes,
            "source": f"https://www.php.net/ChangeLog-{cur[0]}.php"}


def endoflife(product, cycle):
    try:
        for row in json.loads(fetch(f"https://endoflife.date/api/{product}.json", timeout=15)):
            if row.get("cycle") == cycle:
                eol = row.get("eol")
                if eol is True or (isinstance(eol, str) and dt.date.fromisoformat(eol) <= dt.date.today()):
                    return f"⚠ EOL: {product} {cycle} はサポート終了 ({eol})。EOL後の脆弱性は記載されないため結果は網羅的ではありません"
                return f"サポート中: security support={row.get('support')} eol={eol}"
    except Exception as e:  # noqa: BLE001
        return f"EOL情報取得失敗: {e}"
    return None


# ---------------------------------------------------------------- OpenJDK
JDK_BASE = "https://openjdk.org/groups/vulnerability/advisories/"


def _jdk_get(inp, name):
    if inp:
        p = os.path.join(inp, name if name else "index.html")
        return read_file(p) if os.path.exists(p) else None
    return fetch(JDK_BASE + (name or ""))


def parse_jdk_advisory(text):
    """→ (affected_map {feature: max_affected_tuple/str}, rows [(cve, comp, cvss, {feature: bool})])"""
    m = re.search(r"affected versions are\s+(.+?)\s*,?\s*and earlier", strip_tags(text), re.I)
    affected = {}
    if m:
        for tok in re.split(r",\s*", m.group(1)):
            tok = tok.strip()
            if re.match(r"^\d", tok):
                affected[java_tuple(tok)[0]] = tok
    rows = []
    for table in re.findall(r"<table.*?</table>", text, re.S | re.I):
        if "CVE" not in table:
            continue
        trs = re.findall(r"<tr.*?</tr>", table, re.S | re.I)
        header = None
        for tr in trs:
            cells = [strip_tags(c) for c in re.findall(r"<t[hd][^>]*>(.*?)</t[hd]>", tr, re.S | re.I)]
            if header is None and any("CVE" in c for c in cells) and not CVE_RE.search(" ".join(cells)):
                header = cells
                continue
            if header and cells and CVE_RE.match(cells[0]):
                cols = {}
                for i, h in enumerate(header):
                    if re.fullmatch(r"\d+", h) and i < len(cells):
                        cols[int(h)] = cells[i].strip() != ""
                rows.append((CVE_RE.match(cells[0]).group(0), cells[1] if len(cells) > 1 else "",
                             cells[2] if len(cells) > 2 else "", cols))
    return affected, rows


def check_openjdk(version, inp=None, **_):
    cur = java_tuple(version)
    feat = cur[0]
    index = _jdk_get(inp, None)
    dates = sorted({d.replace("/", "-") for d in re.findall(r"(\d{4}[-/]\d{2}[-/]\d{2})", index)}, reverse=True)
    out, notes, latest_feats, latest = [], [], None, None
    for d in dates:
        page = _jdk_get(inp, d)
        if page is None:
            continue
        affected, rows = parse_jdk_advisory(page)
        if latest_feats is None:
            latest_feats = set(affected)
        if feat not in affected:
            if latest_feats and feat > max(latest_feats):
                break
            continue
        aff = java_tuple(affected[feat])
        if latest is None:
            latest = f"{affected[feat]} の次のアップデート以降 ({d} CPU)"
        if cur > aff:
            break  # これ以前のアドバイザリは適用済み
        for cve, comp, cvss, cols in rows:
            if cols.get(feat):
                out.append(finding(cve, parse_date(d), f"{d} CPU ({affected[feat]} 以前が影響)",
                                   comp, severity=cvss.split()[0] if cvss else None, ref=JDK_BASE + d))
    if latest_feats is not None and feat not in latest_feats:
        notes.append(f"⚠ 最新アドバイザリに Java {feat} が含まれていません (OpenJDK上流のサポート外の可能性)。"
                     "ベンダー(Temurin/Corretto/Oracle等)のサポート状況を確認してください")
    notes.append("OpenJDKアドバイザリは四半期(1/4/7/10月の第3火曜)公開。該当月以外は新規0件が通常です")
    return {"latest": latest or "(該当なし=最新CPU適用済み)", "findings": out, "notes": notes, "source": JDK_BASE}


# ---------------------------------------------------------------- Packagist / Composer
def check_packagist(version, package, inp=None, **_):
    url = "https://packagist.org/api/security-advisories/?" + urllib.parse.urlencode({"packages[]": package})
    data = json.loads(read_file(inp) if inp else fetch(url))
    out = []
    for adv in data.get("advisories", {}).get(package, []):
        if not match_constraint(version, adv.get("affectedVersions", "")):
            continue
        rid = adv.get("remoteId") or adv.get("advisoryId")
        id_ = adv.get("cve") or rid
        out.append(finding(id_, parse_date(adv.get("reportedAt")), f"範囲外へ更新 (影響: {adv.get('affectedVersions')})",
                           adv.get("title"), adv.get("severity"), adv.get("link"),
                           aliases=[x for x in [rid] if x and x != id_]))
    return {"latest": None, "findings": out, "notes": [], "source": url}


# ---------------------------------------------------------------- OSV
def check_osv(version, package, ecosystem, inp=None, **_):
    if inp:
        data = json.loads(read_file(inp))
    else:
        body = json.dumps({"package": {"name": package, "ecosystem": ecosystem}, "version": version}).encode()
        data = json.loads(fetch("https://api.osv.dev/v1/query", data=body))
    out = []
    for v in data.get("vulns", []):
        ids = [v["id"]] + v.get("aliases", [])
        cve = next((i for i in ids if i.startswith("CVE-")), v["id"])
        fixed = sorted({e["fixed"] for a in v.get("affected", []) for r in a.get("ranges", [])
                        for e in r.get("events", []) if "fixed" in e}, key=vtuple)
        sev = (v.get("database_specific") or {}).get("severity")
        out.append(finding(cve, parse_date(v.get("published")), ", ".join(fixed) or None,
                           v.get("summary") or v.get("details", "")[:200], sev,
                           f"https://osv.dev/vulnerability/{v['id']}", aliases=[i for i in ids if i != cve]))
    return {"latest": None, "findings": out, "notes": [], "source": "https://osv.dev"}


# ---------------------------------------------------------------- 手動レコード
def check_records(version, inp, **_):
    """records JSON: [{"id":"CVE-..","date":"YYYY-MM-DD","fixed_in":"x.y.z" | "affected":"<constraint>",
    "desc":"..","severity":"..","ref":".."}]  fixed_in があれば version < fixed_in で該当"""
    out = []
    for r in json.loads(read_file(inp)):
        if "affected" in r:
            hit = match_constraint(version, r["affected"])
        elif r.get("fixed_in"):
            hit = vtuple(version) < vtuple(r["fixed_in"])
        else:
            hit = True
        if hit:
            out.append(finding(r["id"], parse_date(r.get("date")), r.get("fixed_in") or r.get("affected"),
                               r.get("desc", ""), r.get("severity"), r.get("ref"), r.get("aliases")))
    return {"latest": None, "findings": out, "notes": ["手動レコードに基づく結果"], "source": inp}


# ---------------------------------------------------------------- 実行・出力
def run_target(t, since, until):
    p = t["product"].lower()
    label = t.get("label") or {"composer": "Composer", "php": "PHP", "openjdk": "OpenJDK"}.get(p) or t.get("package") or p
    try:
        if p == "php":
            r = check_php(t["version"], t.get("input"))
        elif p in ("openjdk", "java", "jdk"):
            r = check_openjdk(t["version"], t.get("input"))
        elif p == "composer":
            r = check_packagist(t["version"], "composer/composer", t.get("input"))
        elif p == "packagist":
            r = check_packagist(t["version"], t["package"], t.get("input"))
        elif p == "osv":
            r = check_osv(t["version"], t["package"], t["ecosystem"], t.get("input"))
        elif p == "records":
            r = check_records(t["version"], t["input"])
        else:
            raise ValueError(f"未対応の product: {p}")
    except Exception as e:  # noqa: BLE001
        return {"target": label, "version": t.get("version"), "error": f"{type(e).__name__}: {e}"}
    seen, fs = set(), []
    for f in r["findings"]:
        if f["id"] in seen:
            continue
        seen.add(f["id"])
        d = parse_date(f["date"])
        f["in_period"] = bool(d and since <= d <= until)
        fs.append(f)
    fs.sort(key=lambda f: f["date"] or "", reverse=True)
    return {"target": label, "product": p, "version": t["version"], "latest": r["latest"],
            "vulnerable": bool(fs), "new_in_period": [f["id"] for f in fs if f["in_period"]],
            "all_unpatched": [f["id"] for f in fs], "findings": fs, "notes": r["notes"], "source": r["source"]}


def print_text(results, since, until):
    print(f"脆弱性チェック  実施日 {dt.date.today()}  集計期間 {since} 〜 {until}\n")
    for r in results:
        print(f"■ {r['target']} {r.get('version')}")
        if "error" in r:
            print(f"  ERROR: {r['error']}\n")
            continue
        if r.get("latest"):
            print(f"  最新: {r['latest']}")
        for n in r["notes"]:
            print(f"  {n}")
        if not r["findings"]:
            print("  結果: 該当 CVE なし\n")
            continue
        print(f"  期間内の新規 ({len(r['new_in_period'])}件): {', '.join(r['new_in_period']) or 'なし'}")
        print(f"  未修正 合計 {len(r['findings'])}件:")
        for f in r["findings"]:
            mark = "[NEW] " if f["in_period"] else ""
            al = f" ({', '.join(f['aliases'])})" if f["aliases"] else ""
            print(f"    {mark}{f['id']}{al}  {f['date'] or ''}  sev={f['severity'] or '-'}  修正: {f['fixed_in'] or '-'}")
            print(f"        {f['desc']}")
        print()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--since")
    ap.add_argument("--until")
    ap.add_argument("--json", action="store_true")
    sp = ap.add_subparsers(dest="cmd", required=True)
    for name in ("php", "openjdk", "composer"):
        s = sp.add_parser(name)
        s.add_argument("version", nargs="?")
        s.add_argument("--input")
        if name == "php":
            s.add_argument("--detect", action="store_true", help="php コマンドから自動検出")
    s = sp.add_parser("packagist"); s.add_argument("package"); s.add_argument("version"); s.add_argument("--input")
    s = sp.add_parser("osv"); s.add_argument("ecosystem"); s.add_argument("package"); s.add_argument("version"); s.add_argument("--input")
    s = sp.add_parser("records"); s.add_argument("product_name"); s.add_argument("version"); s.add_argument("input")
    s = sp.add_parser("batch"); s.add_argument("targets", help="targets.json")
    a = ap.parse_args()

    since, until = default_period()
    if a.since:
        since = dt.date.fromisoformat(a.since)
    if a.until:
        until = dt.date.fromisoformat(a.until)

    if a.cmd == "batch":
        targets = json.loads(read_file(a.targets))
    else:
        t = {"product": a.cmd, "version": getattr(a, "version", None), "input": getattr(a, "input", None)}
        if a.cmd == "php" and getattr(a, "detect", False):
            t["version"] = subprocess.run(["php", "-r", "echo PHP_VERSION;"], capture_output=True, text=True, check=True).stdout.strip()
        if a.cmd == "packagist":
            t["package"] = a.package
        if a.cmd == "osv":
            t.update(package=a.package, ecosystem=a.ecosystem, label=f"{a.package} ({a.ecosystem})")
        if a.cmd == "records":
            t["label"] = a.product_name
        if not t["version"]:
            ap.error("バージョンを指定してください")
        targets = [t]

    results = [run_target(t, since, until) for t in targets]
    if a.json:
        print(json.dumps({"checked_at": dt.date.today().isoformat(),
                          "period": {"since": since.isoformat(), "until": until.isoformat()},
                          "results": results}, ensure_ascii=False, indent=2))
    else:
        print_text(results, since, until)
    sys.exit(1 if any("error" in r for r in results) else 0)


if __name__ == "__main__":
    main()
```