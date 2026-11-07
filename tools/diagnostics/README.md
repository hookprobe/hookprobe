# tools/diagnostics

| Tool | What |
|---|---|
| [`cm5-relay.py`](cm5-relay.py) | Power-cycles the CM5 bench board and asserts nRPIBOOT through a 2-channel USB relay, so it can be reflashed without anyone touching it |
| [`os/kernel/tools/mc-e2e-metal.sh`](../../os/kernel/tools/mc-e2e-metal.sh) | Metal acceptance run against a live CM5 |
| [`os/kernel/tools/gate-r-run.py`](../../os/kernel/tools/gate-r-run.py) | Separation-matrix (Gate R) run |

Serial console: FTDI at 115200. The CM5 prints its boot timing, device identity (`[NETCP] pk=`)
and Mission Control address on it.
