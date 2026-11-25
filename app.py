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

# Rolling window in seconds (default: 3600 = 1 hour)
DEFAULT_WINDOW_SECONDS = max(10, int(os.getenv("WINDOW_SECONDS", "3600")))

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
ip_timestamps = {}  # ip -> deque of epoch timestamps (combined Nginx + HAProxy)
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


def prune_and_count_ips(now=None):
  """Prunes timestamps outside the rolling window and returns active hit counts per IP."""
  if now is None:
    now = time.time()
  cutoff = now - window_seconds
  active_counts = {}
  empty_ips = []

  for ip, dq in ip_timestamps.items():
    while dq and dq[0] < cutoff:
      dq.popleft()
    if dq:
      active_counts[ip] = len(dq)
    else:
      empty_ips.append(ip)

  for ip in empty_ips:
    del ip_timestamps[ip]

  return active_counts


def build_top_ips(limit=10, now=None):
  """Returns the top N active IPs (Nginx + HAProxy combined) within the rolling window."""
  active_counts = prune_and_count_ips(now)
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
      # Detect log rotation (file truncated or replaced)
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
      dq = ip_timestamps.setdefault(ip, deque())
      dq.append(now)
      source_counts[source] += 1
      if target:
        target_counts[target] += 1

      top_ips = build_top_ips(10, now=now)
      ip_window_count = len(ip_timestamps.get(ip, ()))

      geo_data["source"] = source
      geo_data["target"] = target or "—"
      geo_data["ip_count"] = ip_window_count

      payload = {
          "marker": geo_data,
          "top_ips": top_ips,
          "top_targets": build_top_targets(5),
          "sources": dict(source_counts),
          "window_seconds": window_seconds,
      }

    try:
      event_queue.put_nowait(json.dumps(payload))
    except queue.Full:
      try:
        event_queue.get_nowait()
        event_queue.put_nowait(json.dumps(payload))
      except queue.Empty:
        pass


def start_watchers():
  for path in LOG_FILES:
    t = threading.Thread(target=watch_log_file, args=(path,), daemon=True)
    t.start()


start_watchers()


@app.route("/")
def index():
  return render_template("index.html", window_seconds=window_seconds)


@app.route("/api/config", methods=["GET", "POST"])
def api_config():
  global window_seconds
  if request.method == "POST":
    data = request.get_json(silent=True) or {}
    try:
      new_window = int(data.get("window_seconds", window_seconds))
      if 10 <= new_window <= 86400:
        with state_lock:
          window_seconds = new_window
          top_ips = build_top_ips(10)
        payload = {
            "top_ips": top_ips,
            "window_seconds": window_seconds,
        }
        try:
          event_queue.put_nowait(json.dumps(payload))
        except queue.Full:
          pass
        return jsonify({"ok": True, "window_seconds": window_seconds})
    except (TypeError, ValueError):
      pass
    return jsonify({"ok": False, "error": "Invalid window_seconds (10..86400)"}), 400

  with state_lock:
    prune_and_count_ips()
  return jsonify({"window_seconds": window_seconds})


@app.route("/stream")
def stream():
  def event_stream():
    while True:
      try:
        msg = event_queue.get(timeout=15)
        yield f"data: {msg}\n\n"
      except queue.Empty:
        # Periodically prune stale IPs so expired entries drop off even when traffic is quiet
        with state_lock:
          top_ips = build_top_ips(10)
          current_window = window_seconds
        yield f"data: {json.dumps({'top_ips': top_ips, 'window_seconds': current_window})}\n\n"

  return Response(event_stream(), mimetype="text/event-stream")


if __name__ == "__main__":
  app.run(host="0.0.0.0", port=5000, threaded=True)
