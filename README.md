# vuln-monthly-check

使用中のソフトウェア/モジュールのバージョンに脆弱性 (CVE) が残っていないかを **月次で調査** し、該当する CVE 番号を返す Claude スキルです。
PHP から始まり、現在は OpenJDK・Composer・各種パッケージにも対応しています。

## できること

- 指定バージョンに **残っている CVE (未修正)** を一覧化
- そのうち **集計期間 (既定: 前月) に新たに公表された CVE** を `[NEW]` で区別
- 修正版・公表日・深刻度・概要・出典 URL を併記
- 複数製品・複数環境 (本番/ステージング等) を一括チェック
- サポート終了 (EOL) バージョンの警告

## 使い方

Claude に話しかけるだけで動きます。

```
PHP 8.4.24 と Java 17.0.20 と Composer 2.10.2 の脆弱性チェックして
```

- バージョンはパッチ番号まで指定してください (`8.4` ではなく `8.4.24`)。
- 未指定の場合、Claude が `php -v` / `java -version` / Dockerfile 等から取得を試み、分からなければ質問します。
- 集計期間を変えたいときは「2026年8月分で」のように伝えてください。

## 対応製品

| product | 対象 | 情報源 | 「期間内」の判定日 |
|---|---|---|---|
| `php` | PHP 本体 | [php.net ChangeLog](https://www.php.net/ChangeLog-8.php) | 修正版のリリース日 |
| `openjdk` | OpenJDK (Temurin / Corretto 等のビルドも可) | [OpenJDK Vulnerability Advisories](https://openjdk.org/groups/vulnerability/advisories/) | アドバイザリ公開日 |
| `composer` | Composer 本体 | [Packagist Security Advisories API](https://packagist.org/apidoc#list-security-advisories) | 報告日 |
| `packagist` | 任意の Composer パッケージ (例: `laravel/framework`) | 同上 | 報告日 |
| `osv` | npm / PyPI / Maven / Go / RubyGems / crates.io / NuGet 等 | [OSV.dev](https://osv.dev) | 公開日 |
| `records` | 上記以外 (Node.js 本体, nginx, MySQL 等) | ベンダーのセキュリティ告知・NVD から作るレコード JSON | 記載日 |

### 判定ロジック

- **php** — 同一ブランチで、対象より新しいリリースで修正された CVE を「残存」と判定
- **openjdk** — 四半期アドバイザリの「affected versions are …, and earlier」に対象が含まれ、かつリスク表の該当メジャー列に印がある CVE を「残存」と判定
- **composer / packagist** — `affectedVersions` 制約 (例 `>=2.3.0,<2.10.3`) に対象が含まれれば「残存」。CVE 未採番のものは GHSA ID で返す
- **osv** — OSV.dev がバージョン一致を判定。CVE エイリアスがあれば CVE 番号で返す
- **records** — `fixed_in` 未満、または `affected` 制約に一致すれば「残存」

## スクリプト単体での実行

スキル本体 (SKILL.md) の付録にある `vuln_check.py` は Python 3 標準ライブラリのみで動作します。

```bash
python3 -I vuln_check.py php 8.4.24
python3 -I vuln_check.py php --detect                    # ローカルの php から自動検出
python3 -I vuln_check.py openjdk 17.0.20                 # 8u452 / 1.8.0_452 形式も可
python3 -I vuln_check.py composer 2.10.2
python3 -I vuln_check.py packagist laravel/framework 10.48.0
python3 -I vuln_check.py osv npm lodash 4.17.20
python3 -I vuln_check.py records "Node.js" 24.18.0 node_records.json
python3 -I vuln_check.py batch targets.json              # 一括
python3 -I vuln_check.py --json --since 2026-09-01 --until 2026-09-30 batch targets.json
```

| オプション | 説明 |
|---|---|
| `--since` / `--until` | 集計期間 (YYYY-MM-DD)。既定は前月1日〜前月末日 |
| `--json` | JSON で出力 |
| `--input` | 取得済みデータを使う (php/packagist/osv: ファイル、openjdk: ディレクトリ) |

終了コード: 全対象成功で `0`、いずれかの取得に失敗すると `1`。

### targets.json (一括チェック)

毎月同じ対象を調べる場合は、この一覧を保存しておくと便利です。

```json
[
  {"product": "php", "version": "8.4.24", "label": "PHP(本番)"},
  {"product": "openjdk", "version": "17.0.20"},
  {"product": "composer", "version": "2.10.2"},
  {"product": "packagist", "package": "laravel/framework", "version": "10.48.0"},
  {"product": "osv", "ecosystem": "npm", "package": "lodash", "version": "4.17.20"},
  {"product": "records", "version": "24.18.0", "label": "Node.js", "input": "node_records.json"}
]
```

### records JSON (その他製品・手動データ)

```json
[
  {"id": "CVE-2026-56846", "date": "2026-07-29", "fixed_in": "24.18.1",
   "severity": "High", "desc": "HTTP/2 retained headers bypass maxSessionMemory",
   "ref": "https://nodejs.org/en/blog/vulnerability/july-2026-security-releases"},
  {"id": "CVE-2026-59944", "date": "2026-10-02", "affected": ">=2.3.0,<2.10.3"}
]
```

`fixed_in` (このバージョン未満が影響) か `affected` (Composer 形式の制約) のどちらかを指定します。

## 出力例

```
## 脆弱性チェック結果 (2026年9月分)

### PHP 8.4.24 — 脆弱性あり (4件) / 最新 8.4.26
今月の新規: CVE-2026-91767, CVE-2026-91768, CVE-2026-91769, CVE-2025-1218
| CVE | 公表日 | 修正版 | 概要 |
|---|---|---|---|
| CVE-2026-91767 [NEW] | 2026-09-24 | 8.4.26 | OpenSSL: 細工された証明書でヒープバッファオーバーフロー |
...

### OpenJDK 17.0.20 — 該当 CVE なし
### Composer 2.10.2 — 脆弱性あり (2件) / 2.10.3 で修正

まとめ: 要対応 2件 (PHP→8.4.26, Composer→2.10.3)
```

## ネットワークに直接アクセスできない場合

Claude の作業環境によっては、情報源への直接アクセスが制限されることがあります。その場合 Claude は次の順で対応します。

1. ユーザーの PC が接続されていれば、PC 上でスクリプトを実行
2. Web 取得機能で情報源を読み込み、`--input` でスクリプトに渡す
3. 取得した告知内容から records JSON を作成して判定

## 注意事項・制限

- **CVE 番号やバージョンは取得データにあるものだけを返します。** 推測で補うことはありません。
- **OpenJDK** のアドバイザリは四半期 (1/4/7/10月の第3火曜) のみ公開されるため、それ以外の月は「新規0件」が通常です。
- **EOL バージョン**は、サポート終了後に見つかった脆弱性が告知されないため、「該当なし」でも安全とは限りません。警告とアップグレード推奨を出します。
- **Node.js 本体**は現在専用の取得処理がなく、[公式セキュリティリリース告知](https://nodejs.org/en/blog/vulnerability) から records JSON を作って判定します。
- 深刻度 (CVSS) の詳細が必要な場合は、依頼すれば NVD から補足します。
- 本スキルはセキュリティ診断の補助ツールです。最終判断は各ベンダーの公式情報を確認してください。
