from collections import Counter, deque
import json
import os
import queue
import re
import socket
import threading
import time
from flask import Flask, Response, jsonify, render_template, request
import geoip2.database

app = Flask(__name__)

# Support LOG_FILES (comma-separated) with fallback to LOG_FILE
raw_log_files = (
    os.getenv("LOG_FILES")
    or os.getenv("LOG_FILE", "/logs/nginx/access.log,/logs/haproxy.log")
)
LOG_FILES = [p.strip() for p in raw_log_files.split(",") if p.strip()]
GEOIP_DB_PATH = os.getenv("GEOIP_DB_PATH", "/data/GeoLite2-City.mmdb")

# Rolling window for Top 10 IPs (default: 3600 = 1 hour)
DEFAULT_WINDOW_SECONDS = max(10, int(os.getenv("WINDOW_SECONDS", "3600")))

# Active connection TTL in seconds (default: 60s) — controls active count & live map markers
DEFAULT_ACTIVE_TTL_SECONDS = max(5, int(os.getenv("ACTIVE_TTL_SECONDS", "60")))

# Match IPv4 at start of Nginx line OR after "haproxy[pid]: " (with optional :port)
NGINX_IP_REGEX = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3})\b")
HAPROXY_IP_REGEX = re.compile(
    r"\bhaproxy(?:\[\d+\])?:\s+(\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?\b"
)

# Match HTTP request path in Nginx access logs: "GET /path HTTP/1.1"
NGINX_URL_REGEX = re.compile(
    r'"(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE|CONNECT)\s+([^\s?"]+)',
    re.IGNORECASE,
)

# Match HAProxy backend/server right after: <ip[:port]> [<date>] <frontend> <backend/server>
HAPROXY_BACKEND_REGEX = re.compile(
    r"\bhaproxy(?:\[\d+\])?:\s+\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\s+\[[^\]]+\]\s+\S+\s+(\S+)"
)

socket.setdefaulttimeout(1.5)

geoip_reader = None
try:
  if os.path.exists(GEOIP_DB_PATH):
    geoip_reader = geoip2.database.Reader(GEOIP_DB_PATH)
    print(f"Base GeoIP chargée avec succès depuis {GEOIP_DB_PATH}")
  else:
    print(f"Attention: Base GeoIP introuvable à l'emplacement {GEOIP_DB_PATH}")
except Exception as e:
  print(f"Erreur lors du chargement de la base GeoIP: {e}")

window_seconds = DEFAULT_WINDOW_SECONDS
active_ttl_seconds = DEFAULT_ACTIVE_TTL_SECONDS

ip_timestamps = {}  # ip -> deque of epoch timestamps for Top 10 window
active_ip_timestamps = {}  # ip -> deque of epoch timestamps for active TTL
ip_geo_meta = {}  # ip -> latest geo/source/target metadata while active
target_counts = Counter()
source_counts = Counter()
hostname_cache = {}
event_queue = queue.Queue(maxsize=1000)
state_lock = threading.Lock()


def detect_source(line):
  if "haproxy[" in line or " haproxy:" in line:
    return "haproxy"
  return "nginx"


def extract_ip(line, source):
  if source == "haproxy":
    match = HAPROXY_IP_REGEX.search(line)
    if match:
      return match.group(1)
  match = NGINX_IP_REGEX.search(line)
  return match.group(1) if match else None


def extract_target(line, source):
  """Returns the requested URL for Nginx, or [haproxy] <backend/server> for HAProxy."""
  if source == "haproxy":
    match = HAPROXY_BACKEND_REGEX.search(line)
    if match:
      return f"[haproxy] {match.group(1)}"
    return "[haproxy] unknown-backend"

  match = NGINX_URL_REGEX.search(line)
  return match.group(1) if match else None


def resolve_hostname(ip):
  if ip in hostname_cache:
    return hostname_cache[ip]
  try:
    host, _, _ = socket.gethostbyaddr(ip)
    hostname_cache[ip] = host
  except Exception:
    hostname_cache[ip] = "—"
  return hostname_cache[ip]


def get_geoip(ip):
  if (
      ip.startswith("127.")
      or ip.startswith("192.168.")
      or ip.startswith("10.")
      or ip.startswith("172.")
  ):
    return None
  if not geoip_reader:
    return None
  try:
    response = geoip_reader.city(ip)
    if response.location.latitude and response.location.longitude:
      return {
          "ip": ip,
          "hostname": resolve_hostname(ip),
          "lat": response.location.latitude,
          "lon": response.location.longitude,
          "city": response.city.name or "Ville inconnue",
          "country": response.country.name or "Pays inconnu",
      }
  except Exception:
    pass
  return None


def prune_deque_map(ts_map, max_age_seconds, now):
  """Prunes timestamps older than now - max_age_seconds and returns active counts."""
  cutoff = now - max_age_seconds
  counts = {}
  expired_keys = []

  for key, dq in ts_map.items():
    while dq and dq[0] < cutoff:
      dq.popleft()
    if dq:
      counts[key] = len(dq)
    else:
      expired_keys.append(key)

  for key in expired_keys:
    del ts_map[key]

  return counts, expired_keys


def build_top_ips(limit=10, now=None):
  if now is None:
    now = time.time()
  active_counts, _ = prune_deque_map(ip_timestamps, window_seconds, now)
  ranked = sorted(active_counts.items(), key=lambda kv: kv[1], reverse=True)[:limit]
  return [
      {
          "ip": ip,
          "hostname": resolve_hostname(ip),
          "count": count,
      }
      for ip, count in ranked
  ]


def build_top_targets(limit=5):
  return [
      {
          "target": target,
          "count": count,
      }
      for target, count in target_counts.most_common(limit)
  ]


def build_active_snapshot(now=None):
  """Returns current active connections, active markers, and expired IPs."""
  if now is None:
    now = time.time()
  active_counts, expired_ips = prune_deque_map(
      active_ip_timestamps, active_ttl_seconds, now
  )
  for ip in expired_ips:
    ip_geo_meta.pop(ip, None)

  markers = []
  total_active_hits = 0
  for ip, hit_count in active_counts.items():
    total_active_hits += hit_count
    meta = ip_geo_meta.get(ip)
    if meta:
      m = dict(meta)
      m["ip_count"] = hit_count
      markers.append(m)

  return {
      "active_connections": len(active_counts),
      "active_hits": total_active_hits,
      "active_markers": markers,
      "expired_ips": expired_ips,
      "active_ttl_seconds": active_ttl_seconds,
  }


def enqueue_payload(payload_dict):
  raw = json.dumps(payload_dict)
  try:
    event_queue.put_nowait(raw)
  except queue.Full:
    try:
      event_queue.get_nowait()
      event_queue.put_nowait(raw)
    except queue.Empty:
      pass


def watch_log_file(filename):
  """Continuously reads new lines from a single log file and pushes parsed events."""
  while not os.path.exists(filename):
    print(f"Attention: {filename} introuvable. En attente...")
    time.sleep(2)

  print(f"Surveillance active sur {filename}")
  f = open(filename, "r", errors="replace")
  f.seek(0, 2)

  while True:
    line = f.readline()
    if not line:
      try:
        current_size = os.stat(filename).st_size
        if current_size < f.tell():
          f.close()
          f = open(filename, "r", errors="replace")
      except OSError:
        time.sleep(1)
        continue
      time.sleep(0.5)
      continue

    source = detect_source(line)
    ip = extract_ip(line, source)
    if not ip:
      continue

    geo_data = get_geoip(ip)
    if not geo_data:
      continue

    target = extract_target(line, source)
    now = time.time()

    with state_lock:
      ip_timestamps.setdefault(ip, deque()).append(now)
      active_ip_timestamps.setdefault(ip, deque()).append(now)
      source_counts[source] += 1
      if target:
        target_counts[target] += 1

      geo_data["source"] = source
      geo_data["target"] = target or "—"
      ip_geo_meta[ip] = dict(geo_data)

      snapshot = build_active_snapshot(now=now)
      top_ips = build_top_ips(10, now=now)

      payload = {
          **snapshot,
          "top_ips": top_ips,
          "top_targets": build_top_targets(5),
          "sources": dict(source_counts),
          "window_seconds": window_seconds,
      }

    enqueue_payload(payload)


def reaper_loop():
  """Periodically prunes expired active connections so counts drop and markers vanish."""
  last_signature = None
  while True:
    time.sleep(1)
    now = time.time()
    with state_lock:
      snapshot = build_active_snapshot(now=now)
      top_ips = build_top_ips(10, now=now)
      sig = (
          snapshot["active_connections"],
          snapshot["active_hits"],
          tuple(snapshot["expired_ips"]),
          tuple((m["ip"], m["ip_count"]) for m in snapshot["active_markers"]),
      )
      if sig != last_signature:
        last_signature = sig
        payload = {
            **snapshot,
            "top_ips": top_ips,
            "window_seconds": window_seconds,
        }
        enqueue_payload(payload)


def start_watchers():
  for path in LOG_FILES:
    t = threading.Thread(target=watch_log_file, args=(path,), daemon=True)
    t.start()
  reaper = threading.Thread(target=reaper_loop, daemon=True)
  reaper.start()


start_watchers()


@app.route("/")
def index():
  return render_template(
      "index.html",
      window_seconds=window_seconds,
      active_ttl_seconds=active_ttl_seconds,
  )


@app.route("/api/config", methods=["GET", "POST"])
def api_config():
  global window_seconds, active_ttl_seconds
  if request.method == "POST":
    data = request.get_json(silent=True) or {}
    try:
      new_window = int(data.get("window_seconds", window_seconds))
      new_ttl = int(data.get("active_ttl_seconds", active_ttl_seconds))
      if 10 <= new_window <= 86400 and 5 <= new_ttl <= 3600:
        now = time.time()
        with state_lock:
          window_seconds = new_window
          active_ttl_seconds = new_ttl
          snapshot = build_active_snapshot(now=now)
          top_ips = build_top_ips(10, now=now)
        enqueue_payload({
            **snapshot,
            "top_ips": top_ips,
            "window_seconds": window_seconds,
        })
        return jsonify({
            "ok": True,
            "window_seconds": window_seconds,
            "active_ttl_seconds": active_ttl_seconds,
        })
    except (TypeError, ValueError):
      pass
    return jsonify({"ok": False, "error": "Invalid parameters"}), 400

  with state_lock:
    snapshot = build_active_snapshot()
  return jsonify({
      "window_seconds": window_seconds,
      "active_ttl_seconds": active_ttl_seconds,
      "active_connections": snapshot["active_connections"],
  })


@app.route("/stream")
def stream():
  def event_stream():
    with state_lock:
      initial = {
          **build_active_snapshot(),
          "top_ips": build_top_ips(10),
          "top_targets": build_top_targets(5),
          "sources": dict(source_counts),
          "window_seconds": window_seconds,
      }
    yield f"data: {json.dumps(initial)}\n\n"

    while True:
      try:
        msg = event_queue.get(timeout=15)
        yield f"data: {msg}\n\n"
      except queue.Empty:
        yield ": keep-alive\n\n"

  return Response(event_stream(), mimetype="text/event-stream")


if __name__ == "__main__":
  app.run(host="0.0.0.0", port=5000, threaded=True)
