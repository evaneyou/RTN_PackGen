import json, sqlite3, sys

db = sqlite3.connect(sys.argv[1])
db.execute("""CREATE TABLE IF NOT EXISTS rtnp_rx (
    session INTEGER, flow INTEGER, seq INTEGER, size INTEGER, tx_ns INTEGER, t_ns INTEGER)""")
db.execute("""CREATE TABLE IF NOT EXISTS rtnp_interval (
    session INTEGER, idx INTEGER, unix_ms INTEGER, flow INTEGER, name TEXT, proto TEXT,
    sent INTEGER, tx_kbps REAL, rx_packets INTEGER, rx_kbps REAL, delay_avg_ms REAL,
    jitter_ms REAL, jitter_rfc3550_ms REAL, loss_pct REAL, rtt_avg_ms REAL)""")

for path in sys.argv[2:]:
    for line in open(path):
        r = json.loads(line)
        if r.get("ev") == "rx":
            db.execute("INSERT INTO rtnp_rx VALUES (?,?,?,?,?,?)",
                       (r["session"], r["flow"], r["seq"], r["size"], r["tx_ns"], r["t_ns"]))
        elif r.get("type") == "interval":
            for f in r["flows"]:
                rx, rtt = f.get("rx") or {}, f.get("rtt") or {}
                db.execute("INSERT INTO rtnp_interval VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                           (r["session"], r["index"], r["unix_ms"], f["flow"], f["name"], f["proto"],
                            f["sent"], f["tx_kbps"], rx.get("packets"), rx.get("bitrate_kbps"),
                            rx.get("delay_avg_ms"), rx.get("jitter_ms"), rx.get("jitter_rfc3550_ms"),
                            f.get("loss_pct"), rtt.get("avg_ms")))
db.commit()
