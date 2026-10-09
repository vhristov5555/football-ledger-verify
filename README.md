# football-ledger-verify

Check one day of the public forecast ledger of **football.vhristov.com** on
your own computer, without trusting the site.

[English](#english) · [Български](#български)

---

## English

### What this verifies

Every day, before the matches, the site writes its forecasts into a ledger
file and stamps that file through OpenTimestamps; the stamp is later anchored
in a Bitcoin block. Checking one day tells you:

- **when** the record existed — no later than (about) the time of the
  Bitcoin block that carries its stamp; a block's time is set by its miner
  and is only approximate, roughly ±2 hours;
- that it **has not been changed** since — a single changed character gives a
  different file fingerprint, and the stamp is for the original one.

### What it does not verify

- **Whether the forecasts were good.** The ledger proves WHEN a forecast
  existed, not that it was right.
- That the ledger contains every forecast the site ever showed — it proves
  what is in the file, not what is absent from it.
- The no-node check (below) trusts that the two block explorers report the
  block at that height in the real Bitcoin chain. It checks that both return
  the same header, that the header hashes to the block hash and carries valid
  proof of work for its own difficulty, and that its Merkle root matches the
  stamp. With your own Bitcoin node, `ots verify` removes that trust.
- The stamp is independent evidence of the moment of the record. It is not a
  qualified electronic time stamp under Regulation (EU) No 910/2014.

### Get the files

The ledger is served read-only at `https://football.vhristov.com/api/ledger/`:

| URL | What |
| --- | --- |
| `/api/ledger` | index of forecast days (JSON: date, n, root, …) |
| `/api/ledger/errata` | index of published corrections |
| `/api/ledger/<day>.jsonl` | the day-record — one JSON line |
| `/api/ledger/<day>.jsonl.btc.ots` | the Bitcoin-attested OpenTimestamps proof |
| `/api/ledger/<day>.jsonl.ots` | the initial calendar proof (pending; not needed below) |

`<day>` is `YYYY-MM-DD` for forecasts, `facts-YYYY-MM-DD` for the
interesting-facts ledger and `facts-erratum-YYYY-MM-DD` for corrections. The
Bitcoin proof appears usually within a few hours of a day's record, sometimes
up to a day; until then `<day>.jsonl.btc.ots` answers 404 — check an earlier
day.

```sh
curl -O https://football.vhristov.com/api/ledger/2026-10-04.jsonl
curl -O https://football.vhristov.com/api/ledger/2026-10-04.jsonl.btc.ots
```

### The three commands

```sh
# 1. the file's fingerprint (macOS: shasum -a 256 2026-10-04.jsonl)
sha256sum 2026-10-04.jsonl

# 2. the record is whole: n, every leaf commitment and the Merkle root re-derived
python3 -c 'import sys,json,hashlib;H=lambda b:hashlib.sha256(b).digest();r=json.loads(open(sys.argv[1],encoding="utf-8").readline());E=r["leaves"] if "leaves" in r else r["entries"];L=[H(x["canonical_json"].encode()) for x in E];R=lambda l:l[0] if len(l)==1 else R([H(l[i]+l[min(i+1,len(l)-1)]) for i in range(0,len(l),2)]);t=(R(L) if L else H(b"")).hex();ok=[c.hex() for c in L]==[x["commitment"] for x in E] and t==r["root"] and r["n"]==len(E);print("OK "+t if ok else "MISMATCH");sys.exit(0 if ok else 1)' 2026-10-04.jsonl

# 3. the Bitcoin stamp (needs the OpenTimestamps client AND a Bitcoin node)
ots verify -f 2026-10-04.jsonl 2026-10-04.jsonl.btc.ots
```

The `-f` matters: without it `ots verify X.jsonl.btc.ots` looks for a file
called `X.jsonl.btc`, which does not exist.

### The no-node path: `verify.py`

`verify.py` does all three in one go, with the Python standard library only
(3.10+, nothing to install) and **no Bitcoin node**: it parses the proof
itself and fetches each attested block header from **two independent block
explorers** — `mempool.space` and `blockstream.info` — which must agree.

```sh
python3 verify.py 2026-10-04                 # download both files and check
python3 verify.py 2026-10-04 --save-dir .    # … and keep the files
python3 verify.py ./2026-10-04.jsonl         # local file; proof = <file>.btc.ots
python3 verify.py ./day.jsonl --proof ./day.jsonl.btc.ots
python3 verify.py ./2026-10-04.jsonl --skip-bitcoin   # offline; the time is NOT checked
```

Example output (abridged):

```
OK   record 2026-10-04.jsonl: 18 leaves, root 0956c27d…
OK   sha256(2026-10-04.jsonl) = 7296f1fb…
OK   2026-10-04.jsonl.btc.ots commits to exactly this file
OK   Bitcoin block 969792 (0000…6a27bb), time ~2026-10-04 03:21:23 UTC: Merkle root matches; mempool.space and blockstream.info agree
=>   the record existed no later than about 2026-10-04 03:21:23 UTC (block 969792) and has not changed since.
     A block's time is set by its miner: approximate, roughly +/- 2 hours.
```

Exit codes:

| code | meaning |
| --- | --- |
| `0` | every check passed (with `--skip-bitcoin`: the local checks passed and the time was NOT checked) |
| `1` | verification FAILED — the data contradicts the claim (a leaf, the root, the proof digest or a block's Merkle root does not match; a header fails its own hash or proof-of-work check) |
| `2` | could not decide — usage error, missing file, unsupported proof, network error, the two explorers disagreeing with each other, or no Bitcoin attestation yet |

### Tests

```sh
python3 -m unittest discover -s tests -v
```

Offline: the fixtures are one real public day (2026-10-04: an 18-leaf record
with three odd Merkle levels, its calendar proof and its Bitcoin proof) with
the recorded explorer responses for its four Bitcoin blocks, plus the real
66-entry erratum for the `entries` field name. `tests/MUTATIONS.md` lists
the defects the suite was measured to catch.

---

## Български

### Какво проверява

Всеки ден, преди мачовете, сайтът записва прогнозите си във файл от журнала и
подпечатва файла чрез OpenTimestamps; по-късно печатът се вписва в биткойн
блок. Проверката на един ден показва:

- **кога** е съществувал записът — най-късно (приблизително) в момента на
  биткойн блока, в който е вписан печатът му; времето на блока се задава от
  копача и е приблизително, с точност около ±2 часа;
- че **не е променян** след това — промяна дори на един знак дава друг
  отпечатък на файла, а печатът е за оригиналния.

### Какво не проверява

- **Дали прогнозите са били добри.** Журналът доказва КОГА е съществувала
  прогнозата, не че е била вярна.
- Че журналът съдържа всяка прогноза, показвана някога на сайта — проверката
  се отнася до съдържанието на файла, не до това, което липсва в него.
- Проверката без възел (по-долу) разчита, че двете услуги за преглед на
  блокове посочват блока на тази височина в истинската биткойн верига. Тя
  проверява, че двете връщат един и същ заглавен блок, че той се хешира до
  хеша на блока и носи валидно доказателство за работа за собствената си
  трудност, и че коренът на Меркъл в него съвпада с печата. Със собствен
  биткойн възел `ots verify` премахва и това доверие.
- Печатът е независимо свидетелство за момента на записа. Той не е
  квалифициран електронен времеви печат по Регламент (ЕС) № 910/2014.

### Как да вземете файловете

Журналът се сервира само за четене на `https://football.vhristov.com/api/ledger/`
(таблицата с адресите е в английската част по-горе). `<day>` е `ГГГГ-ММ-ДД` за
прогнозите, `facts-ГГГГ-ММ-ДД` за журнала с интересни факти и
`facts-erratum-ГГГГ-ММ-ДД` за корекциите. Печатът в биткойн блок се появява
обикновено до няколко часа след записа за деня, понякога до ден; дотогава
`<day>.jsonl.btc.ots` връща 404 — проверете по-ранен ден.

### Трите команди

1. `sha256sum 2026-10-04.jsonl` — отпечатъкът на файла (на macOS:
   `shasum -a 256 2026-10-04.jsonl`).
2. Командата `python3 -c '…' 2026-10-04.jsonl` от английската част —
   проверява броя `n`, пресмята наново отпечатъка на всяка прогноза и общия
   отпечатък на деня;
   трябва да отпечата `OK` и отпечатъка на деня.
3. `ots verify -f 2026-10-04.jsonl 2026-10-04.jsonl.btc.ots` — печатът в
   биткойн блок; изисква клиента на OpenTimestamps и работещ биткойн възел.
   Без `-f` командата търси файл `2026-10-04.jsonl.btc`, който не съществува.

### Проверка без биткойн възел: `verify.py`

`verify.py` прави и трите проверки наведнъж — само със стандартната
библиотека на Python (3.10+, нищо за инсталиране) и **без биткойн възел**:
сам разчита печата и взима заглавния блок на всеки вписан биткойн блок от
**две независими услуги** — `mempool.space` и `blockstream.info`, които
трябва да съвпадат.

```sh
python3 verify.py 2026-10-04            # изтегля двата файла и ги проверява
python3 verify.py ./2026-10-04.jsonl    # локален файл; печатът = <файл>.btc.ots
```

Изходни кодове: `0` — всички проверки минаха; `1` — проверката е
НЕУСПЕШНА (данните противоречат на твърдението); `2` — не може да се реши
(грешка в употребата, липсващ файл, мрежова грешка, двете услуги се
разминават помежду си или печатът още няма биткойн вписване).

---

MIT License — see `LICENSE`.
