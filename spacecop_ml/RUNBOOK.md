# SpaceCOP-ML — Train & Find False Positives (Runbook)

A copy-paste guide to: combine nominal capture files, train the models, then
replay nominal data back through the trained server to see what it *falsely*
flags as anomalies.

### Two environments — don't mix them up

| | **Ground / build box** (x86 dev machine) | **Pi** (`/opt/pisat/spacecop_ml`) |
|---|---|---|
| Has | Rust toolchain + Python venv | just the static binary |
| Used for | cross-compiling the binary **and training** (needs Python) | running the server in production |
| Run via | `cargo run …` | `/opt/pisat/spacecop_ml/target/release/spacecop_ml server` (svc `pisat-ml`, user `pi`) |

**Training only happens on the ground box** — it shells out to `python`
(`ad_models.py`, tensorflow/sklearn), which isn't on the Pi. The Pi just runs the
cross-compiled **static musl** binary for inference (ONNX via `tract`, no Python).
Training produces `scml_models/`; the Pi uses whatever `scml_models/` sits next to
its binary, so **after retraining you must copy `scml_models/` to the Pi and
restart the service** (see step 4). Ground-box commands below run from the
`spacecop_ml/` source dir.

> Background: the models are **per-packet autoencoders**, one per
> `(CMD|TLM, SYSTEM)`. There are no time/rate/sequence features, so capture
> **duration and the gaps between sessions don't matter** — only how many
> packets per system you collect and how much nominal variety they cover.
> Caveat: monotonic counters / time fields (e.g. `CCSDS_SEQUENCE`,
> `*_SECONDS`, `*CMDPC/*CMDEC`) trained on short captures will read
> out-of-range in the field and cause false positives. See
> `feature_denylist.txt` for the full flagged list.

---

## 0. One-time prerequisites

```bash
# Python env for the training step (ad_models.py uses tensorflow/sklearn)
python3 -m venv venv
source venv/bin/activate            # Windows: .\venv\Scripts\activate
pip install -r requirements.txt
```

The parser DB `instance/cmd_tlm.sqlite` already exists in the repo. Only rebuild
it if the command/telemetry definitions changed:

```bash
# (optional) cd scripts && python build_database.py /path/to/nos3 && cd ..
```

---

## 1. Combine your capture files

Each file must be **one hex packet per line** (same format as
`nominal_data.txt`). The loop guarantees a newline between files so the last
packet of one file and the first of the next don't merge:

```bash
for f in file1.txt file2.txt file3.txt file4.txt; do
    cat "$f"; echo
done > nominal_all.txt

wc -l nominal_all.txt        # sanity check: total packet count
```

---

## 2. Train

Keep the Python venv **active** (the Rust step shells out to `python scripts/ad_models.py`).

```bash
cargo run --release -- train nominal_all.txt
```

> Use the **native** `cargo run` (or an x86 `./target/release/spacecop_ml`) here —
> **not** `/opt/pisat/spacecop_ml/target/release/spacecop_ml`. That path is the
> Pi's ARM binary; it has no Python/`scripts/ad_models.py` and can't train. Also
> note `nominal_data.txt` is the old repo **sample** — train on your combined
> `nominal_all.txt`, not that.

What to watch in the output:
- **Per-`(type, system)` sample counts** ("Found N unique combinations… X samples").
  Systems with only a handful of samples will train weak, false-positive-prone
  models — collect more of those before trusting them.
- Trained artifacts land in **`scml_models/CMD|TLM/<SYSTEM>/`**
  (`anomaly_detector.onnx`, `metadata.json`, `scaler.json`, `training_data.json`).

> The anomaly threshold is the **99th percentile of training MSE**, so by
> construction ~1% of the *training* data will trip it. To measure a *true*
> false-positive rate, replay nominal data the model did **not** train on
> (hold a file out in step 1), not the training set itself.

---

## 3. Find the false positives (replay nominal data)

Nominal data replayed through the trained model should produce **no** anomalies —
anything it flags is a false positive. Three terminals. Pick where the **server**
runs:

**Terminal A — the model server** (input :9111, alerts :9112). Either:

*Option A — on the ground box (fastest to iterate; models are already here):*
```bash
cargo run --release -- server
```

*Option B — on the Pi, the real deployed static binary* (`scripts/server_test.py`
is stdlib-only, so run terminals B and C on the Pi against localhost too):
```bash
cd /opt/pisat/spacecop_ml
sudo systemctl stop pisat-ml                 # free port 9111 first
./target/release/spacecop_ml server          # or: sudo systemctl start pisat-ml
# ...evaluate, then when done: sudo systemctl start pisat-ml
```
For Option B the freshly trained `scml_models/` must already be on the Pi — do
**step 4** first.

**Terminal B — pretend to be SpaceCOP and collect alerts** (aggregates stats):
```bash
python scripts/server_test.py       # (python3 scripts/server_test.py on the Pi)
# choose 1  (Act as SpaceCOP, listen on 9112)
```

**Terminal C — replay your nominal hex through the model:**
```bash
# The batch sender SKIPS THE FIRST LINE (expects a CSV header), so prepend a
# throwaway line or you'll lose packet #1:
{ echo "# header line - skipped by the batch sender"; cat nominal_all.txt; } > replay.txt

python scripts/server_test.py
# choose 4  (Batch send from file) and enter:  replay.txt
```
(Use a held-out file here instead of `nominal_all.txt` for a meaningful FP rate.)

**Read the results:** go back to Terminal B and press `Ctrl-C`. It prints
accumulated statistics and writes a timestamped log (path shown when it started).
Every alert over nominal data is a false positive; the breakdown includes:
- counts by **system** and by **mnemonic** (which packet types over-trigger), and
- the **responsible feature** — i.e. exactly which field drove the MSE up.

That `responsible_feature` column is the payoff: if the false positives are
dominated by counter/time fields (`CCSDS_SEQUENCE`, `*_SECONDS`, `*CMDPC` …),
that confirms the denylist and tells you what to exclude next.

---

## 4. Deploy retrained models to the Pi

The Pi's static binary loads whatever `scml_models/` sits beside it — it does
**not** get updated by training on the ground box. After a retrain, push the new
models and restart the service (the binary itself only changes if you recompiled
code — see the cross-compile section in `README.md`):

```bash
# from the ground box (rsync the trained models into the Pi's working dir)
rsync -a scml_models/ pi@<PI_IP>:/opt/pisat/spacecop_ml/scml_models/
# if the parser DB changed too:  rsync -a instance/ pi@<PI_IP>:/opt/pisat/spacecop_ml/instance/

# on the Pi
sudo systemctl restart pisat-ml
journalctl -u pisat-ml -n 30 --no-pager      # expect "Loaded N anomaly detection models"
```

---

## Quick reference

| Action | Where | Command |
|---|---|---|
| Combine files | ground | `for f in f1 f2 f3 f4; do cat "$f"; echo; done > nominal_all.txt` |
| Train | ground | `cargo run --release -- train nominal_all.txt` |
| Run server (eval) | ground | `cargo run --release -- server` |
| Run server (real) | Pi | `cd /opt/pisat/spacecop_ml && ./target/release/spacecop_ml server` |
| Deploy models | ground→Pi | `rsync -a scml_models/ pi@<PI_IP>:/opt/pisat/spacecop_ml/scml_models/` |
| Restart service | Pi | `sudo systemctl restart pisat-ml` |
| Listen for alerts | either | `python scripts/server_test.py` → `1` |
| Replay a file | either | `python scripts/server_test.py` → `4` → `replay.txt` |
| Ports | — | `9111` = hex input, `9112` = alerts out |
| Deployed binary | Pi | `/opt/pisat/spacecop_ml/target/release/spacecop_ml` (static musl, user `pi`) |
| Models output | ground | `scml_models/CMD|TLM/<SYSTEM>/` |
| Flagged features | — | `feature_denylist.txt` |

## Gotchas
- **Training is ground-box only** — it needs Python (`ad_models.py`); the Pi has no Python/cargo, just the static binary.
- **Retraining doesn't update the Pi** — you must `rsync scml_models/` over and `systemctl restart pisat-ml` (step 4).
- On the Pi, `pisat-ml` already owns port 9111 — `systemctl stop pisat-ml` before running the server by hand.
- Batch replay (`option 4`) **drops the first line** of the file — prepend a header line.
- Replaying the **training** file shows ~1% anomalies by design (99th-pct threshold); hold data out for a real FP rate.
- Keep the Python **venv active** for `train` (it invokes `python` for `ad_models.py`).
- The server uses **relative paths** (`instance/`, `scml_models/`) — run it from its own dir (`spacecop_ml/` on the ground box, `/opt/pisat/spacecop_ml` on the Pi).
