# ida-func-call-rank 仕様・サーベイ・モチベーションまとめ

作成日: 2026-05-22  
プロジェクト名: **ida-func-call-rank**  
想定形態: IDA Pro / IDAPython plugin  
採用ライセンス: MIT License

---

## 1. プロジェクト概要

**ida-func-call-rank** は、IDA Proに「全関数を横断した呼び出し関係ランキングビュー」を追加するためのIDAPythonプラグインである。

Ghidraには、関数一覧や呼び出し関係を俯瞰するためのUIがあり、解析初期に「どの関数が多く呼ばれているか」を見る導線として有用である。一方で、IDA Proにもxrefや関数呼び出し関係を確認する機能は存在するものの、**全関数について call count / caller count / callee count を集計し、降順ソートできる専用ビュー**は標準機能としては確認できない。

本プラグインは、IDAが既に持っているxref情報を、解析初期のtriageに使いやすいランキングテーブルとして再提示することを目的とする。

README用の短い説明:

```text
ida-func-call-rank is a lightweight IDAPython plugin that adds a sortable,
Ghidra-like function call-ranking table for fast reverse-engineering triage.
```

より短いキャッチコピー:

```text
Find heavily reused functions at a glance.
```

---

## 2. ツール名・命名方針

### 2.1 正式プロジェクト名

```text
ida-func-call-rank
```

この名前をGitHubリポジトリ名、配布名、READMEタイトルとして採用する。

### 2.2 IDA内の表示名

IDAのメニュー、ウィンドウタイトル、プラグイン表示名では、ユーザに分かりやすい名前を使う。

```text
Function Call Rank
```

または、よりブランド名を出す場合:

```text
CallRank - Function Call Ranking
```

### 2.3 Pythonファイル名

単一ファイルMVPの場合:

```text
ida_func_call_rank.py
```

将来的にモジュール分割する場合:

```text
ida-func-call-rank/
  ida_func_call_rank.py
  callrank/
    __init__.py
    plugin.py
    scanner.py
    model.py
    ui.py
    filters.py
    export.py
    compat.py
```

### 2.4 避ける名前

以下の名前は避ける。

| 名前 | 避ける理由 |
|---|---|
| `HotFunctions` / `HotCalls` | 実行時プロファイリング、hot path、runtime frequencyを連想させる |
| `XrefRank` | xref全般のツールに見えて、function call rankingという目的が薄れる |
| `GhidraCallRank` | Ghidraをツール名に入れると比較対象への依存が強く見える |
| `IDAFunctionCallCountWindow` | 説明的すぎてOSSプロジェクト名として長い |

本ツールは実行時のhotnessを測るものではなく、IDAの静的xrefに基づくtriage補助ツールであるため、`Hot` という語は使わない方針とする。

---

## 3. 背景

リバースエンジニアリングでは、解析初期に「よく呼ばれている関数」を知りたい場面が多い。

典型例:

- ハッシュ計算関数
- 復号・復元ルーチン
- 文字列デコード関数
- API resolver / API wrapper
- allocator wrapper
- ロギング関数
- エラー処理関数
- VM型難読化におけるdispatcher/helper
- 多数の関数から使われる内部utility関数

特に、マルウェア、CTF、crackme、難読化バイナリでは、関数名や型情報がほとんどない状態から解析を始めることが多い。そのような状況では、`Calls In` や `Unique Callers` の降順ランキングは「どこから見るべきか」を判断するためのファーストインプレッションとして有効である。

本プラグインは、意味的な重要度を完全に推定するものではない。あくまで **IDAの静的xrefに基づくheuristic** である。しかし、初心者にとっては解析対象の全体像を掴む補助線になり、熟練者にとっても初動のスクリーニングを短縮できる。

---

## 4. サーベイ結果

### 4.1 IDA標準機能

IDA Proには、呼び出し関係やxrefを調べるための標準機能が存在する。

| 機能 | 標準機能でできること | ida-func-call-rankとの差分 |
|---|---|---|
| Functions view | 全関数の一覧表示 | call count / caller count列がない |
| Cross References window | 現在位置へのxref一覧 | 現在位置中心であり、全関数ランキングではない |
| Cross References Tree | 現在関数を中心にto/from関係を階層表示 | 現在関数中心であり、全関数集計ではない |
| Function calls window | 現在関数のcaller/calleeを表示 | 現在関数中心であり、降順ランキングではない |
| IDAPython xref API | xref情報を取得可能 | 集計・可視化するUIは自前実装が必要 |

Hex-Rays公式ドキュメントによると、IDAのSubviewsにはFunctions、Cross References、Cross References Tree、Function callsなどのビューが存在する。Functions viewは全関数を一覧するが、記載されている列は関数名、セグメント、開始アドレス、関数長、locals/saved registersサイズ、argumentsサイズ、属性フラグなどであり、call count系の列は記載されていない。

Function calls windowも標準で存在するが、これは基本的に現在関数を中心にcaller/calleeを確認するためのビューであり、全関数を横断したランキングビューではない。

### 4.2 IDAPython API

本プラグインの実装に必要な材料はIDAPythonから利用できる。

主に使用するAPI:

| API | 用途 |
|---|---|
| `idautils.Functions()` | 全関数の列挙 |
| `idautils.Chunks(func_ea)` | 関数chunkの列挙 |
| `idautils.Heads(start, end)` | 命令headの列挙 |
| `ida_xref.xrefblk_t()` | xrefの列挙 |
| `ida_xref.fl_CF` | far call xref |
| `ida_xref.fl_CN` | near call xref |
| `ida_xref.XREF_CODE` | code xrefのみを対象にする |
| `ida_xref.XREF_NOFLOW` | 通常の次命令flowを除外する |
| `ida_funcs.get_func(ea)` | アドレスから所属関数を取得 |
| `ida_kernwin.Choose` | カスタム一覧ビュー |
| `ida_idaapi.plugin_t` | IDAプラグイン定義 |

したがって、本プラグインは「IDAに存在しない解析能力を新規に作る」というより、**IDAが既に持つxref情報を、解析初期に使いやすいUIへ変換する**ものと位置づけられる。

### 4.3 既存プラグイン調査

2026-05-22時点の公開情報ベースでは、**全関数のdirect-call fan-in / fan-outを集計し、降順ソートできる専用IDAプラグイン**は確認できなかった。

ただし、これは「絶対に存在しない」と断定するものではない。IDAプラグインのエコシステムには多数の個人実装、古いスクリプト、社内ツール、未公開ツールが存在する可能性があるため、READMEでは以下のような表現が安全である。

```text
IDA provides several xref and function-call views, but we could not find a
built-in or widely used plugin that provides a sortable, whole-program function
call-count ranking table similar to this tool.
```

---

## 5. モチベーション

本ツールの目的は、IDAでバイナリを開いた直後に、**関数単位の静的な呼び出し集中度**を素早く把握できるようにすることである。

### 5.1 ビギナー向けの価値

IDA初心者は、巨大な関数一覧やxrefを前にして「どこから見ればよいか」が分からなくなりがちである。`Unique Callers` や `Calls In` でソートされた一覧は、以下のような直感的な問いに答えやすい。

- どの関数が多くの場所から呼ばれているか？
- 共通処理っぽい関数はどれか？
- importやlibraryを除いた内部関数の中で目立つものはどれか？
- hash/decrypt/dispatcher/helperの候補はどこか？

### 5.2 熟練者向けの価値

熟練者にとっても、最初のtriageを短縮できる。

- 大規模バイナリで見るべき内部関数を絞り込む
- 難読化バイナリでhelper関数候補を見つける
- static xref graphの偏りを即座に確認する
- CSV出力して解析メモや自動triageに流用する

### 5.3 重要な注意点

このツールが示すのは **静的なxref数** であり、実行時の呼び出し頻度ではない。

```text
Calls In != runtime call frequency
```

正しくは以下である。

```text
Calls In = number of static direct call xrefs recognized by IDA
```

したがって、READMEには以下の文言を明記する。

```text
This plugin provides a static xref-based triage heuristic.
It does not measure runtime hotness and does not infer semantic importance.
```

---

## 6. MVP仕様

### 6.1 起動方法

MVPでは以下のいずれか、または両方を提供する。

| 起動方法 | 内容 |
|---|---|
| Plugins menu | `Edit -> Plugins -> Function Call Rank` |
| View menu | `View -> Open subviews -> Function Call Rank` 相当 |
| Hotkey | 例: `Ctrl-Shift-C` |

MVPではプラグインメニュー起動のみでもよい。使い勝手改善として後からViewメニューに追加する。

### 6.2 メインビュー

非モーダルの一覧ウィンドウを表示する。

ウィンドウ名:

```text
Function Call Rank
```

表示形式:

- IDA標準のchooser/list viewer風UI
- ドック可能
- 行選択で関数へジャンプ可能
- Refresh可能
- ソート可能
- CSV出力可能

### 6.3 初期ソート

初期表示は以下を推奨する。

```text
Unique Callers desc
Calls In desc
Calls Out desc
EA asc
```

理由:

- 同じcallerから10回呼ばれている関数より、10個のcallerから1回ずつ呼ばれる関数の方が共通処理として目立つ可能性が高い
- `Calls In` だけだと、同一関数内で繰り返し呼ばれているケースが上位に来やすい
- `Unique Callers` と `Calls In` の両方を持つことで、使われ方の違いを把握できる

---

## 7. 表示列

Chooser に表示する列は以下 (MVP実装済み)。

| 列名 | 型 | 説明 |
|---|---:|---|
| `Unique Callers` | int | 対象関数を呼ぶユニークなcaller関数数 |
| `Calls In` | int | 対象関数へのdirect call xref数 |
| `Unique Callees` | int | 対象関数が呼ぶユニークなcallee関数数 |
| `Calls Out` | int | 対象関数内から出るdirect call xref数 |
| `Recursive` | int | 自己再帰call数 (`Calls In` / `Calls Out` にも含む) |
| `Unknown` | int | IDAが関数として解決できなかった呼び出し先数 |
| `EA` | address | 関数開始アドレス |
| `Name` | string | 関数名 |
| `Segment` | string | 所属セグメント |
| `Size` | int | 関数サイズ |
| `Flags` | string | lib / thunk / extern 等の簡易表示 |

将来的な拡張列 (未実装):

| 列名 | 説明 |
|---|---|
| `Import Calls Out` | import/externalへのcall数 |
| `Jump In` | tail-call候補のjump参照数 |
| `Jump Out` | 関数外へのjump参照数 |
| `Data Refs In` | 関数ポインタ等のdata ref数 |
| `Score` | heuristicな総合スコア |
| `Comment` | 関数コメントまたはrepeatable comment |

---

## 8. カウント定義

### 8.1 Direct call xref

MVPでは、IDA xref種別のうち以下のみをdirect callとして扱う。

```python
ida_xref.fl_CF  # call far
ida_xref.fl_CN  # call near
```

通常の命令flowは除外する。

```python
ida_xref.XREF_CODE | ida_xref.XREF_NOFLOW
```

### 8.2 Calls In

`Calls In` は、対象関数へ入るdirect call xrefの総数。

例:

```text
foo() から bar() を3回call
baz() から bar() を1回call
```

この場合:

```text
bar.Calls In       = 4
bar.Unique Callers = 2
```

推奨実装では、call targetを `ida_funcs.get_func(target_ea)` で正規化する。これにより、関数先頭だけでなく、まれな関数途中へのcallも所属関数へのincoming callとして扱える。

### 8.3 Unique Callers

`Unique Callers` は、対象関数を呼ぶユニークなcaller関数の数。

同じcaller関数内から対象関数が5回呼ばれている場合:

```text
Calls In       = 5
Unique Callers = 1
```

5つの異なるcaller関数から1回ずつ呼ばれている場合:

```text
Calls In       = 5
Unique Callers = 5
```

この2つは解析上の意味が異なるため、両方を表示する。

### 8.4 Calls Out

`Calls Out` は、対象関数のbody内にあるdirect call xrefの総数。

関数chunkを列挙し、各instruction headから出るcode xrefを確認する。`fl_CF` / `fl_CN` のみをdirect callとして数える。

### 8.5 Unique Callees

`Unique Callees` は、対象関数から呼ばれるユニークなcallee関数数。

同じcalleeを複数回呼ぶ場合、`Calls Out` は増えるが `Unique Callees` は1として数える。

### 8.6 Recursive Calls

自己再帰はデフォルトでは `Calls In` と `Calls Out` の両方に含めたうえで、`Recursive` 列に自己再帰call数を別途表示する。`Unknown` 列も同様に、IDAが関数として解決できなかった outgoing call の本数を表示する。

---

## 9. フィルタ仕様

MVPでは最低限、以下のフィルタを提供する。

| フィルタ | 初期値 | 説明 |
|---|---:|---|
| Exclude library functions | ON | IDAがlibrary functionとして認識した関数を除外 |
| Exclude thunks | ON | thunk関数を除外 |
| Exclude extern/imports | ON | import/external symbolを除外 |
| Exclude zero callers | OFF | incoming callが0の関数を非表示 |
| Internal functions only | OFF | 同一バイナリ内部関数のみ表示 |
| Include recursive calls | ON | 自己再帰をカウントに含める |

将来的な追加フィルタ:

| フィルタ | 説明 |
|---|---|
| Segment allowlist | `.text` など特定セグメントのみ表示 |
| Segment denylist | `.plt`, `.idata`, `extern` などを除外 |
| Name denylist | `j_`, `__imp_`, `nullsub_` などを除外 |
| Min Calls In | 指定値未満を非表示 |
| Min Unique Callers | 指定値未満を非表示 |
| Hide compiler/runtime helpers | `__security_check_cookie` 等を除外 |
| Hide known imports | libc / WinAPI等を除外 |

---

## 10. UI操作仕様

### 10.1 行選択

行をダブルクリック、またはEnterで対象関数へジャンプする。

### 10.2 ソート

各数値列で降順/昇順ソートできるようにする。

MVPでは、実装容易性を優先して以下のどちらかを採用する。

1. IDA chooserの標準ソートに任せる
2. プラグイン側で明示的にソート状態を持つ

IDAバージョン差で標準ソートが不安定な場合は、プラグイン側で以下を保持する。

```python
sort_key = "unique_callers"
sort_order = "desc"
```

### 10.3 コンテキストメニュー

右クリックメニューに以下を追加する。

| メニュー | 説明 |
|---|---|
| Jump to function | 関数先頭へ移動 |
| Show xrefs to | IDA標準のxref表示を開く |
| Copy function name | 関数名をコピー |
| Copy address | EAをコピー |
| Refresh | 再集計 |
| Export CSV | CSVとして保存 |
| Toggle library functions | library除外のON/OFF |
| Toggle thunks | thunk除外のON/OFF |
| Toggle imports | import除外のON/OFF |
| Count mode | direct calls only / calls + jumps / all code refs |

### 10.4 ステータス表示

ウィンドウ下部またはタイトルに、集計条件を表示する。

例:

```text
Function Call Rank - 1243 functions, direct calls only, lib/thunk/import hidden
```

---

## 11. Count Mode

### 11.1 MVP: Direct Calls Only

MVPでは以下のみを対象にする。

```python
ida_xref.fl_CF
ida_xref.fl_CN
```

これは最も意味が明確で、誤検出が少ない。

### 11.2 Optional: Calls + Tail-call-like Jumps

次バージョンで、関数境界をまたぐjumpをtail call候補として別列に表示する。

対象候補:

```python
ida_xref.fl_JF
ida_xref.fl_JN
```

ただし、jumpは通常の分岐、switch、エラーハンドリング、関数境界認識ミスと混同しやすい。そのため、MVPではdirect callと混ぜず、`Jump In` / `Jump Out` として別列にする。

### 11.3 Optional: Data Refs In

関数ポインタ配列、vtable、callback tableなどから参照される関数を検出するため、data refsを別列で表示する。

ただし、data refは「実際に呼ばれる」とは限らないため、`Calls In` に混ぜない。

---

## 12. 実装方針

### 12.1 実装言語

MVPはIDAPythonで実装する。

理由:

- 導入が簡単
- IDAユーザが改造しやすい
- xref列挙、関数列挙、UI chooserがIDAPythonから利用可能
- OSSとして公開しやすい

将来的にパフォーマンスが問題になった場合のみ、C++ plugin化を検討する。

### 12.2 推奨ディレクトリ構成

初期MVP:

```text
ida-func-call-rank/
  README.md
  LICENSE
  ida_func_call_rank.py
  docs/
    design_ja.md
```

中長期:

```text
ida-func-call-rank/
  README.md
  LICENSE
  pyproject.toml
  ida_func_call_rank.py
  callrank/
    __init__.py
    plugin.py
    scanner.py
    model.py
    ui.py
    filters.py
    export.py
    compat.py
  tests/
    samples/
    expected/
  docs/
    design.md
    limitations.md
    screenshots/
```

### 12.3 主要クラス

```text
CallRankOptions
  - include_library: bool
  - include_thunks: bool
  - include_imports: bool
  - include_recursive: bool
  - count_mode: str

FunctionCallStats
  - ea: int
  - name: str
  - segment: str
  - size: int
  - flags: str
  - calls_in: int
  - unique_callers: set[int]
  - calls_out: int
  - unique_callees: set[int]
  - recursive_calls: int
  - unknown_callees: int

CallRankScanner
  - scan() -> list[FunctionCallStats]
  - scan_function(func_ea)
  - classify_xref(xref)

CallRankChooser
  - OnGetSize()
  - OnGetLine()
  - OnSelectLine()
  - OnRefresh()
  - OnPopup()
```

---

## 13. 集計アルゴリズム

推奨アルゴリズムは、**全関数のoutgoing xrefsを走査し、その結果からincoming側も同時に構築する**方式。

### 13.1 手順

1. IDAの自動解析完了を待つ。
2. 全関数を列挙する。
3. 各関数について `FunctionCallStats` を初期化する。
4. 各関数のchunkを列挙する。
5. 各instruction headから出るxrefを列挙する。
6. xref typeが `fl_CF` / `fl_CN` ならdirect callとして扱う。
7. call targetを `ida_funcs.get_func(target_ea)` でcallee functionへ正規化する。
8. caller側の `Calls Out` / `Unique Callees` を更新する。
9. callee側の `Calls In` / `Unique Callers` を更新する。
10. UI表示用に行へ変換する。
11. フィルタを適用する。
12. ソートする。

### 13.2 擬似コード

```python
for func in all_functions:
    stats[func.start_ea] = FunctionCallStats(func)

for caller in all_functions:
    for chunk_start, chunk_end in function_chunks(caller):
        for head in instruction_heads(chunk_start, chunk_end):
            for xref in code_xrefs_from(head, no_flow=True):
                if xref.type not in {fl_CF, fl_CN}:
                    continue

                callee = get_func(xref.to)

                stats[caller.start_ea].calls_out += 1

                if callee is None:
                    stats[caller.start_ea].unknown_callees += 1
                    continue

                caller_ea = caller.start_ea
                callee_ea = callee.start_ea

                stats[caller_ea].unique_callees.add(callee_ea)
                stats[callee_ea].calls_in += 1
                stats[callee_ea].unique_callers.add(caller_ea)

                if caller_ea == callee_ea:
                    stats[caller_ea].recursive_calls += 1
```

---

## 14. MVP実装スケルトン

以下はMVPの方向性を示す簡略版である。実際のOSS版では、エラー処理、フィルタ、CSV出力、バージョン互換性、コンテキストメニューを追加する。

```python
# ida_func_call_rank.py

import ida_idaapi
import ida_kernwin
import ida_funcs
import ida_name
import ida_segment
import ida_xref
import idautils

CALL_XREF_TYPES = {
    ida_xref.fl_CF,  # call far
    ida_xref.fl_CN,  # call near
}


def iter_code_xrefs_from(ea):
    xb = ida_xref.xrefblk_t()
    ok = xb.first_from(ea, ida_xref.XREF_CODE | ida_xref.XREF_NOFLOW)
    while ok:
        if xb.iscode:
            yield xb
        ok = xb.next_from()


def scan_call_rank():
    stats = {}

    for ea in idautils.Functions():
        f = ida_funcs.get_func(ea)
        if not f:
            continue
        stats[f.start_ea] = {
            "ea": f.start_ea,
            "name": ida_name.get_name(f.start_ea) or "",
            "segment": "",
            "size": f.end_ea - f.start_ea,
            "calls_in": 0,
            "unique_callers": set(),
            "calls_out": 0,
            "unique_callees": set(),
            "unknown_callees": 0,
            "recursive_calls": 0,
        }

        seg = ida_segment.getseg(f.start_ea)
        if seg:
            stats[f.start_ea]["segment"] = ida_segment.get_segm_name(seg) or ""

    for caller_ea in list(stats.keys()):
        caller_func = ida_funcs.get_func(caller_ea)
        if not caller_func:
            continue

        for start, end in idautils.Chunks(caller_ea):
            for head in idautils.Heads(start, end):
                for xb in iter_code_xrefs_from(head):
                    if xb.type not in CALL_XREF_TYPES:
                        continue

                    stats[caller_ea]["calls_out"] += 1

                    callee_func = ida_funcs.get_func(xb.to)
                    if not callee_func:
                        stats[caller_ea]["unknown_callees"] += 1
                        continue

                    callee_ea = callee_func.start_ea
                    stats[caller_ea]["unique_callees"].add(callee_ea)

                    if callee_ea in stats:
                        stats[callee_ea]["calls_in"] += 1
                        stats[callee_ea]["unique_callers"].add(caller_ea)

                    if caller_ea == callee_ea:
                        stats[caller_ea]["recursive_calls"] += 1

    rows = []
    for row in stats.values():
        rows.append({
            **row,
            "unique_callers_count": len(row["unique_callers"]),
            "unique_callees_count": len(row["unique_callees"]),
        })

    rows.sort(
        key=lambda r: (
            r["unique_callers_count"],
            r["calls_in"],
            r["calls_out"],
            -r["ea"],
        ),
        reverse=True,
    )
    return rows


class FunctionCallRankChooser(ida_kernwin.Choose):
    def __init__(self):
        cols = [
            ["Unique Callers", 14 | ida_kernwin.Choose.CHCOL_DEC],
            ["Calls In", 10 | ida_kernwin.Choose.CHCOL_DEC],
            ["Unique Callees", 14 | ida_kernwin.Choose.CHCOL_DEC],
            ["Calls Out", 10 | ida_kernwin.Choose.CHCOL_DEC],
            ["EA", 16 | ida_kernwin.Choose.CHCOL_EA],
            ["Name", 40 | ida_kernwin.Choose.CHCOL_FNAME],
            ["Segment", 12 | ida_kernwin.Choose.CHCOL_PLAIN],
            ["Size", 10 | ida_kernwin.Choose.CHCOL_DEC],
        ]
        super().__init__(
            "Function Call Rank",
            cols,
            flags=ida_kernwin.Choose.CH_CAN_REFRESH | ida_kernwin.Choose.CH_RESTORE,
        )
        self.items = []
        self.refresh_items()

    def refresh_items(self):
        self.items = scan_call_rank()

    def OnGetSize(self):
        return len(self.items)

    def OnGetLine(self, n):
        r = self.items[n]
        return [
            str(r["unique_callers_count"]),
            str(r["calls_in"]),
            str(r["unique_callees_count"]),
            str(r["calls_out"]),
            f"{r['ea']:X}",
            r["name"],
            r["segment"],
            str(r["size"]),
        ]

    def OnSelectLine(self, n):
        ida_kernwin.jumpto(self.items[n]["ea"])
        return [ida_kernwin.Choose.NOTHING_CHANGED]

    def OnRefresh(self, n):
        self.refresh_items()
        return [ida_kernwin.Choose.ALL_CHANGED] + self.adjust_last_item(n)


_view = None


def show_function_call_rank():
    global _view
    _view = FunctionCallRankChooser()
    _view.Show(False)


class FunctionCallRankPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_UNL
    comment = "Show function call ranking table"
    help = "Show sortable function call ranking table"
    wanted_name = "Function Call Rank"
    wanted_hotkey = "Ctrl-Shift-C"

    def init(self):
        return ida_idaapi.PLUGIN_OK

    def run(self, arg):
        show_function_call_rank()

    def term(self):
        pass


def PLUGIN_ENTRY():
    return FunctionCallRankPlugin()
```

---

## 15. CSV出力仕様

### 15.1 出力ファイル名

デフォルト:

```text
<idb_name>_function_call_rank.csv
```

### 15.2 CSV列

```csv
ea,name,segment,size,flags,unique_callers,calls_in,unique_callees,calls_out,recursive_calls,unknown_callees
```

### 15.3 EA表記

EAは16進数文字列で出力する。

```text
0x140001000
```

### 15.4 用途

CSV出力は以下に使える。

- 解析メモ
- 他ツールとの連携
- レポート作成
- サンプル間比較
- 自動triage結果の保存

---

## 16. 制限事項

READMEには、以下を明記する。

### 16.1 静的xrefベースである

本プラグインは、実行時の呼び出し回数を測るものではない。

```text
Calls In = runtime call frequency
```

ではない。

正しくは:

```text
Calls In = number of static direct call xrefs recognized by IDA
```

### 16.2 indirect callは原則として数えない

以下は、IDAが明示的なxrefとして解決していない限り数えられない。

- function pointer call
- virtual call
- callback
- jump table経由のcall
- obfuscated dispatch
- dynamically resolved API

### 16.3 関数境界に依存する

IDAの関数認識が間違っている場合、集計結果も間違う。

### 16.4 import/thunkが上位に来やすい

標準ライブラリ、import thunk、PLT、compiler helperがランキング上位に来ることがある。そのため、デフォルトではlibrary / thunk / importを隠す。

### 16.5 重要度のランキングではない

高い `Calls In` は「多く呼ばれている」ことを示すが、「解析上もっとも重要」とは限らない。

README用の文言:

```text
This plugin provides a static xref-based triage heuristic.
It does not measure runtime hotness and does not infer semantic importance.
```

---

## 17. 想定ユースケース

### 17.1 難読化解除

多数の関数から呼ばれる小さな関数を見つける。

候補:

- hash helper
- decrypt helper
- rotate/xor helper
- VM helper
- string decoder

### 17.2 マルウェア解析

共通処理を早期に把握する。

候補:

- API resolver
- C2 string decoder
- config decryptor
- logging/debug check
- wrapper around WinAPI

### 17.3 CTF / crackme

初心者が解析対象の構造を掴む。

候補:

- validation helper
- checksum routine
- input transform
- common comparison function

### 17.4 大規模バイナリのtriage

巨大なIDBで、最初に見るべき内部関数を絞り込む。

---

## 18. テスト仕様

### 18.1 toy binary

以下のような小さなCプログラムを用意する。

```c
void hash(void) {}
void decrypt(void) { hash(); }
void parse_a(void) { hash(); hash(); }
void parse_b(void) { hash(); }
void unused(void) {}

int main(void) {
    decrypt();
    parse_a();
    parse_b();
}
```

期待値:

```text
hash:
  Calls In       = 4
  Unique Callers = 3

decrypt:
  Calls In       = 1
  Unique Callers = 1
  Calls Out      = 1

unused:
  Calls In       = 0
  Unique Callers = 0
```

### 18.2 recursive case

```c
int fact(int n) {
    if (n <= 1) return 1;
    return n * fact(n - 1);
}
```

期待値:

```text
fact:
  Recursive Calls >= 1
```

### 18.3 import/thunk case

Windows PEまたはELFで、import関数が上位に出ることを確認する。その後、`Exclude imports` で非表示になることを確認する。

### 18.4 tail call case

最初のMVPではtail callを `Calls In` に混ぜない。将来の `Jump In` 実装時に別列で表示されることを確認する。

### 18.5 IDA標準xrefとの整合性

任意の関数について、IDA標準の `Xrefs to` と本プラグインの `Calls In` が一致するか確認する。ただし、通常flow、jump、data refを除外している点に注意する。

---

## 19. パフォーマンス要件

MVPでは、手動Refresh時に全関数を再走査してよい。

目標:

| 規模 | 目標 |
|---|---|
| 1,000 functions | 1秒以内を目指す |
| 10,000 functions | 数秒以内を目指す |
| 50,000 functions以上 | progress表示、キャンセル対応を検討 |

大規模IDBでは、以下を検討する。

- progress表示
- cancel可能なscan
- 結果キャッシュ
- filter/sortだけなら再scanしない
- autoanalysis完了後のみscan
- UI表示時に遅延更新

---

## 20. 受け入れ条件

MVPの受け入れ条件は以下。

1. IDAからプラグインを起動できる。
2. 全関数の一覧が表示される。
3. `Calls In` が表示される。
4. `Unique Callers` が表示される。
5. `Calls Out` が表示される。
6. `Unique Callees` が表示される。
7. デフォルトで降順ランキングされる。
8. 行をダブルクリックすると関数へジャンプする。
9. Refreshできる。
10. library / thunk / importを除外できる。
11. CSV出力できる。
12. READMEに静的xrefベースであることが明記されている。

---

## 21. ロードマップ

### Phase 0: Survey / README

- 既存IDA機能との差分を整理
- README作成
- スクリーンショット予定位置を作成
- limitationを明記

### Phase 1: MVP Scanner

- 全関数列挙
- direct call xref列挙
- `Calls In`
- `Unique Callers`
- `Calls Out`
- `Unique Callees`
- コンソール出力

### Phase 2: Chooser UI

- 非モーダル一覧ビュー
- double-click jump
- Refresh
- デフォルトソート
- 数値列表示

### Phase 3: Filters

- library除外
- thunk除外
- import除外
- zero caller除外
- segment filter

### Phase 4: Export

- CSV出力
- クリップボードコピー
- 選択行のみ出力

### Phase 5: Advanced Metrics

- `Jump In`
- `Jump Out`
- `Data Refs In`
- `Recursive Calls`
- `Unknown Callees`
- `Score`

### Phase 6: Polish

- アイコン
- メニュー統合
- 設定保存
- バージョン互換性対応
- サンプルIDBでのテスト
- GitHub Release

---

## 22. README草案

```markdown
# ida-func-call-rank

A lightweight IDAPython plugin that adds a sortable function call-ranking table
for IDA Pro.

`ida-func-call-rank` ranks functions by static call relationships recognized by
IDA, including incoming direct calls, unique callers, outgoing direct calls, and
unique callees.

It is useful for early-stage reverse-engineering triage, especially when looking
for frequently reused helpers such as hash routines, decryptors, API wrappers,
dispatchers, and common utility functions.

## Features

- Sortable function call ranking table
- Incoming direct call count
- Unique caller count
- Outgoing direct call count
- Unique callee count
- Jump to function on double-click
- Optional filters for library/thunk/import functions
- CSV export

## Important

This is not a runtime profiler.

The counts are based on static IDA xrefs. Indirect calls, unresolved function
pointers, obfuscated dispatch, and incorrect function boundaries may affect the
result.

In other words:

`Calls In` means the number of static direct call xrefs recognized by IDA, not
runtime call frequency.
```

---

## 23. GitHub issue案

### 23.1 MVP issue

```markdown
## Implement MVP scanner

Implement a scanner that walks all IDA functions and collects direct call xrefs.

Required metrics:

- Calls In
- Unique Callers
- Calls Out
- Unique Callees
- Unknown Callees
- Recursive Calls

Direct calls should be defined as:

- ida_xref.fl_CF
- ida_xref.fl_CN

Normal flow xrefs should be excluded with XREF_NOFLOW.
```

### 23.2 UI issue

```markdown
## Implement Function Call Rank chooser

Create a non-modal chooser window named `Function Call Rank`.

Columns:

- Unique Callers
- Calls In
- Unique Callees
- Calls Out
- EA
- Name
- Segment
- Size
- Flags

Double-clicking a row should jump to the function start address.
```

### 23.3 CSV issue

```markdown
## Add CSV export

Add CSV export for the current table.

Columns:

ea,name,segment,size,flags,unique_callers,calls_in,unique_callees,calls_out,recursive_calls,unknown_callees
```

---

## 24. 最終的な位置づけ

**ida-func-call-rank** の価値は、IDAに存在しない解析能力を新しく作ることではなく、IDAが既に持っているxref情報を、解析初期に使いやすいランキングビューへ変換することにある。

IDAにはxref、Function calls window、Cross References Treeなどの強力な機能がある。しかし、それらは基本的に「現在位置」「現在関数」を中心にした探索向けUIである。本プラグインはそれを補完し、**プログラム全体を横断したcall-count based overview** を提供する。

OSSとして公開する場合の一文:

```text
ida-func-call-rank adds a sortable, Ghidra-like function call-count ranking view
to IDA Pro for fast reverse-engineering triage.
```

---

## 25. 参考資料

- Hex-Rays Docs: IDA Subviews  
  https://docs.hex-rays.com/ida-9.2/user-guide/user-interface/subviews

- IDAPython Docs: `ida_xref`  
  https://python.docs.hex-rays.com/ida_xref/index.html

- IDAPython Docs: `ida_kernwin`  
  https://python.docs.hex-rays.com/ida_kernwin/index.html

- IDAPython Docs: `ida_idaapi`  
  https://python.docs.hex-rays.com/ida_idaapi/index.html

