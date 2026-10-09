# 8. Extras: post-quantum and learned model

These three additions are optional. None of them changes a verdict or a score. Each is shown as
context next to the rules.

## Post-quantum key-exchange fingerprint (`qlure/pqc/kex.py`)

The SSH decoy reads the key-exchange list each client offers, before the handshake completes.

- It logs `kex_offered` (the list), `kex_fp` (a short hash of the list) and `pqc_capable` (whether
  the client offers a post-quantum exchange).
- It uses the client's version line as `client_fp`, which helps group sessions.
- The schema only allows these three fields on SSH events.
- The dashboard shows one chart: the share of SSH sessions offering a post-quantum exchange, split
  by verdict.

What it does **not** do: detect quantum attacks, or affect any rule or score. It is a hint about
which tool the visitor uses.

The decoy offers `mlkem768x25519-sha256` first, then AsyncSSH's defaults. The
`sntrup761x25519-sha512@openssh.com` exchange is offered only if the installed AsyncSSH build has
it. The pinned build does not.

## Signed checkpoints (`qlure/pqc/signing.py`)

Signing protects against someone rewriting the whole history, including the hash chain, since a
rewritten chain would still pass `qlure verify`.

| Command | What it does |
|---|---|
| `qlure keygen` | Makes an ML-DSA-65 key pair (a `.key` and a `.pub` file) |
| `qlure sign` | Signs the current chain head and stores it as a checkpoint |
| `qlure verify` | Checks the chain against the archive. `--pub` names the public key used for checking signatures (default `data/signing.pub`) |

Rules for keeping it meaningful:

- Keep the `.key` file **off the decoy host**. Anyone holding it can re-chain and re-sign history.
- Pin the `.pub` file. Compare it against a copy you trust.
- It needs `liboqs`, installed with `pip install 'qlure[pqc]'`. The key library is built the first
  time it is imported.
- The Docker images do not include `liboqs`. Run `qlure sign` on a trusted machine that has a copy
  of the database.

## Learned second opinion (`qlure/ml/`)

A small logistic-regression model, written in plain Python with no randomness, so the same input
always gives the same output.

- **Input:** behaviour only, as counts, rates and ratios (`features.py`). It never sees tool names,
  addresses or User-Agents, so it cannot simply memorise a scanner's name.
- **Output:** a score and its three biggest factors, shown beside the rule verdict.
- **Disagrees mark:** shown when the rules say Noteworthy but the model scores below 0.2, or the rules
  say not Noteworthy but the model scores 0.8 or more.
- **Training:** `qlure ml train captures/tuning`. It refuses fewer than 10 sessions, fewer than 3 of
  either kind (malicious or benign), and any folder named `heldout`.
- **Evaluation:** `qlure eval <folder> --model data/model.json` scores the model on labelled sessions.
  It is marked NOT VALID if any of those sessions were in its training data.
- **Shipped model:** none. A model can only exist once real labelled captures do, and the first
  real-tool run is recorded in [page 10](10-known-limits.md).

There is no generative text model anywhere in the project. Explanations stay the same every time,
and nothing needs internet access.
