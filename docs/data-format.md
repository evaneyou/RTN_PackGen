# Results and data format

RTNP does not write to any database. It produces plain, line-based results, and you load them into whatever
you use for storage and analysis (PostgreSQL, TimescaleDB, ClickHouse, InfluxDB, Elasticsearch, SQLite, a
data lake, and so on). This page describes what RTNP writes so you can build that loader.

## Where results come from

| Source | How to get it | Contents |
|---|---|---|
| Live summaries | `rtnp-send ... --json -i 10s` (stdout) | One JSON object per line: an `interval` line per interval, and a `final` line at the end |
| Event logs | `-l file.jsonl` on `rtnp-send` and `rtnp-recv`, or `--log-server host:port` to collect them centrally with `rtnp-logd` | One JSON object per line: flow start and end, and one record per received packet (per sent packet with `--log-packets`) |
| Tables | `rtnp-decode tx.jsonl rx.jsonl -f csv` (or `-f json`) | Per-flow totals; add `-i <ms>` for a time series |

All JSON output is newline-delimited (one object per line), which most log shippers and bulk loaders accept
directly. New fields may be added in later versions, so loaders should ignore fields they don't know.
Fields that could not be measured are `null`.

## Interval line (`--json` with `-i`)

```json
{"type":"interval","session":1405253173,"index":1,"unix_ms":1791902290430,"elapsed_s":3.04,
 "interval_s":3.04,"warnings":[],
 "flows":[{"flow":1,"name":"flow1","proto":"udp","sent":102,"tx_kbps":67.6,"lost":0,"loss_pct":0.0,
           "rx":{...},"rtt":null,"reverse":null}]}
```

| Field | Meaning |
|---|---|
| `type` | `interval` |
| `session` | Session id (integer; see Session ids below) |
| `index` | Interval number, starting at 1 |
| `unix_ms` | Unix time in milliseconds when the interval was reported |
| `elapsed_s`, `interval_s` | Seconds since the start and the length of this interval |
| `warnings` | List of text warnings (for example the receiver restarted) |
| `flows[]` | One object per flow, below |

Each entry in `flows[]` has `flow` (id), `name`, `proto`, `sent` (packets sent in the interval), `tx_kbps`,
`lost`, `loss_pct`, and these nested objects, each `null` when not measured:

- `rx`: receiver-side numbers (a Summary, below). Needs a control channel (`-c`).
- `rtt`: `count`, `min_ms`, `avg_ms`, `max_ms`, `jitter_ms`.
- `reverse`, `reverse_lost`, `reverse_loss_pct`: the return stream of a two-way call.

## Final line

`{"type":"final","session":...,"flows":[...]}` with one report per flow: `session`, `flow`, `name`, `proto`,
`sent`, `sent_bytes`, `late`, `rx` (Summary), `rtt`, `lost_vs_tx`, `reverse` (Summary), and `verdict` when
quality limits were given.

## Summary object (`rx` and `reverse`)

| Field | Unit | Meaning |
|---|---|---|
| `packets`, `bytes` | count | Received |
| `lost`, `loss_pct` | count, % | Missing packets, from sequence gaps |
| `reordered` | count | Packets that arrived out of order |
| `duration_s` | s | Measurement window |
| `bitrate_kbps`, `pps` | kbit/s, packets/s | Rates |
| `delay_min_ms`, `delay_avg_ms`, `delay_max_ms`, `delay_stddev_ms` | ms | One-way delay |
| `jitter_ms` | ms | Mean absolute difference of consecutive delays |
| `jitter_rfc3550_ms` | ms | Smoothed interarrival jitter as defined in RFC 3550 |
| `delay_relative` | boolean | `true` when delay is relative to the first packet (plain-RTP streams carry no send time), so it can be negative and only differences are meaningful |
| `tos` | integer | TOS byte of the latest packet (DSCP is `tos >> 2`), when the platform reports it |

## Event log records (`-l`, `--log-server`)

Every line has an `ev` field naming the record type. Times (`t_ns`, `tx_ns`) are nanoseconds since the Unix
epoch on the clock of the machine that wrote the record.

| `ev` | When | Fields |
|---|---|---|
| `flow_start` | Flow begins | `session`, `flow`, `role` (`tx` or `rx`), `name`, `proto`, `peer`, `t_ns` |
| `tx` | Each packet sent (only with `--log-packets`) | `session`, `flow`, `seq`, `size`, `t_ns` |
| `rx` | Each packet received | `session`, `flow`, `seq`, `size`, `tx_ns` (sender's timestamp), `t_ns` (arrival) |
| `rtt` | Each round-trip probe answered | `session`, `flow`, `seq`, `size`, `t_ns`, `rtt_ns` |
| `flow_end` | Flow ends | `session`, `flow`, `t_ns`, `sent`, `bytes`, `late` |

One-way delay for a packet is `t_ns - tx_ns` and is only meaningful when the two machines' clocks are
synchronised (NTP or PTP). Plain-RTP streams carry no send time, so use `jitter_ms` or relative delay there.

## CSV from `rtnp-decode`

Per-flow totals (`-f csv`):

```text
session,flow,name,proto,sent,rx_packets,rx_bytes,lost,loss_pct,bitrate_kbps,pps,delay_avg_ms,delay_max_ms,jitter_ms
```

Time series (`-f csv -i 2000`, one row per 2000 ms bucket):

```text
session,flow,t_ms,packets,bitrate_kbps,pps,delay_avg_ms,jitter_ms
```

## Session ids

A session id is a 32-bit number. JSON output writes it as a decimal integer (`1405253173`); the CSV and text
output write it as eight hex digits (`53c27635`). They are the same value, so convert one form when you join
across sources, for example in Python `int("53c27635", 16)`, or in PostgreSQL `('x' || '53c27635')::bit(32)::int`
(use `bigint` if you need to avoid a negative number for ids above 2^31).

## Loading into a database

RTNP leaves this step to standard tools, so you can use any database. Three common approaches:

1. **Bulk-load the CSV.** Create a table with the columns above and use your database's bulk loader. For
   PostgreSQL, as one example: `\copy rtnp_summary FROM 'summary.csv' CSV HEADER`.
2. **Ship the JSON lines.** Point a log shipper (Vector, Fluent Bit, Logstash and similar) at the `--json`
   output or the `rtnp-logd` files, and send them to your store, where JSON columns and ingest pipelines
   can index the fields.
3. **Write a small loader.** `examples/load_results.py` reads the event logs and interval lines and inserts
   them into SQLite using only the Python standard library. The same code works with another database by
   changing the connection and the placeholder style (`?` becomes `%s` for most PostgreSQL drivers).

   ```sh
   python3 examples/load_results.py results.db rx.jsonl send.jsonl
   ```

   It creates two tables, `rtnp_rx` (one row per received packet) and `rtnp_interval` (one row per flow per
   interval), which you can then query:

   ```sql
   SELECT idx, rx_packets, jitter_ms, loss_pct FROM rtnp_interval ORDER BY idx;
   SELECT count(*), avg(t_ns - tx_ns) / 1e6 AS avg_delay_ms FROM rtnp_rx;
   ```

The SQLite loader is tested against real output from this version. The PostgreSQL lines above are examples and
have not been run against a PostgreSQL server.
