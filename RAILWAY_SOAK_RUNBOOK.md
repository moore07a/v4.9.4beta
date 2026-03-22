# Railway Stability / Leak Verification Runbook

## 1) Runtime gauges now available
The app exposes these in `GET /health` and `GET /healthz` under `stats.resources`:
- `openSockets`
- `sseListeners`
- `logFileQueueLines`
- `logFileQueueBytes`
- `logFileDroppedLines`
- `logFileDrainPending`
- `logFileStreamReady`

Also monitor existing:
- `stats.memory` (`rssMb`, `heapUsedMb`, `heapTotalMb`, `externalMb`, `arrayBuffersMb`)
- `stats.maxObservedEventLoopLagMs`
- `stats.inFlightRequests`
- `stats.serverErrors`, `stats.serverClientErrors`, `stats.requestTimeouts`

## 2) Synthetic soak test (30–120 mins)
Run against deployed URL:

```bash
node tests/soak-test.js \
  --url https://<your-service>.up.railway.app/health \
  --duration-min 60 \
  --concurrency 8 \
  --rps 20 \
  --timeout-ms 8000
```

The script prints minute summaries and a final JSON with:
- error rate (`5xx + network`) and latency percentiles (`p50/p95/p99`)
- tail samples of runtime gauges from health endpoint

Suggested pass gates:
- error rate < 1%
- no monotonic increase in `rssMb` without leveling
- `openSockets`, `logFileQueueBytes`, and `logFileDroppedLines` stay bounded

## 3) Railway diagnostics to review
In Railway deployment/service metrics & events, inspect:
- restart reason (manual / crash / OOM / platform)
- OOM events and memory ceiling usage
- CPU throttling / sustained high CPU
- concurrent requests and spikes around failures

Correlate timestamps with app logs:
- `[ALERT:RUNTIME] ...`
- `[HEALTH] event-loop-lag=...`
- `[PROCESS] ...` / `[SERVER] ...`
- `[SHUTDOWN] ...`

## 4) Production tuning knobs
Start with defaults, then tune if needed:

```env
LOG_FILE_QUEUE_MAX_LINES=5000
LOG_FILE_QUEUE_MAX_BYTES=2097152
LOG_FILE_QUEUE_WARN_BYTES=1048576
OPEN_SOCKETS_WARN_THRESHOLD=400
SSE_LISTENERS_WARN_THRESHOLD=120
SHUTDOWN_GRACE_MS=10000
```

If pressure persists:
- increase `SHUTDOWN_GRACE_MS` (e.g. 15000)
- lower log volume/sampling in noisy paths
- increase service memory/CPU plan
