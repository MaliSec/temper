---
last_updated: 2026-11-19
---

# 07 Performance

Every release's evidence bundle carries that release's benchmark: the
capture's amd64 run (`bench-gofips-amd64.log`, `bench-control-amd64.log`)
and the native run on each architecture's CI runner
(`suites-*/gofips-bench.log`, E-41). The table below is one amd64 run of
the same benchmark, from 2026-11-19, as a reference point; hosted runners
are shared, so treat any single run as indicative.

## In-image TLS benchmark

`run-tls-bench.sh` runs `node-tls-bench.js` in the Temper node image
(Node 26.13.1, OpenSSL 4.0.3): gofips-only config versus a
default-provider control, identical surfaces (TLS 1.3, ECDSA P-256,
AES-256-GCM-SHA384, prime256v1, SSL_OP_NO_TICKET), 3 rounds each,
medians across rounds (E-25). The concurrent phase runs 100 handshakes,
20 in flight.

| Metric | Control | gofips | Delta |
|---|---|---|---|
| serial handshake median | 2.71 ms | 3.80 ms | +40.0% |
| serial handshake p95 | 3.19 ms | 4.54 ms | +42.1% |
| serial handshakes/sec | 369 | 263 | -28.6% |
| concurrent median | 55.90 ms | 69.53 ms | +24.4% |
| concurrent handshakes/sec | 355 | 270 | -24.0% |
| bulk echo (16 MiB each way) | 125.2 MiB/s | 86.9 MiB/s | -30.6% |
| process CPU, last round | 2610 ms | 3580 ms | +37.2% |
| peak RSS | 105.0 MB | 115.3 MB | +9.8% |

Zero failed handshakes in either run.

Run-to-run variance on one host: serial median delta +9% to +40%, bulk
-25% to -36%. The capture runs the benchmark alongside the other suites,
so host load moves these figures. Treat them as order of magnitude: the
Go path costs roughly a tenth to two fifths of handshake throughput and
about a quarter to a third of bulk throughput.
