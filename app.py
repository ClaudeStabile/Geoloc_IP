from collections import Counter
import json
import os
import re
import socket
import time
from flask import Flask, Response, render_template
import geoip2.database

app = Flask(__name__)

LOG_FILE = os.getenv("LOG_FILE", "/logs/access.log")
GEOIP_DB_PATH = os.getenv("GEOIP_DB_PATH", "/data/GeoLite2-City.mmdb")
IP_REGEX = re.compile(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
# Capture l'URL dans une requête HTTP standard : "GET /chemin HTTP/1.1"
URL_REGEX = re.compile(r'"[A-Z]+\s+([^\s?"]+)')

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

ip_counts = Counter()
url_counts = Counter()
hostname_cache = {}


def resolve_hostname(ip):
  """Résout le nom d'hôte (PTR) d'une IP et le met en cache."""
  if ip in hostname_cache:
    return hostname_cache[ip]
  try:
    host, _, _ = socket.gethostbyaddr(ip)
    hostname_cache[ip] = host
  except Exception:
    hostname_cache[ip] = "—"
  return hostname_cache[ip]


def extract_url(line):
  """Extrait le chemin URL demandé depuis une ligne de log Nginx."""
  match = URL_REGEX.search(line)
  return match.group(1) if match else None


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


def build_top_ips(limit=10):
  """Construit la liste des N IP les plus fréquentes avec leur nom d'hôte."""
  return [
      {
          "ip": ip,
          "hostname": resolve_hostname(ip),
          "count": count,
      }
      for ip, count in ip_counts.most_common(limit)
  ]


def build_top_urls(limit=5):
  """Construit la liste des N URL les plus demandées."""
  return [
      {
          "url": url,
          "count": count,
      }
      for url, count in url_counts.most_common(limit)
  ]


def tail_log(filename):
  if not os.path.exists(filename):
    print(f"Attention: {filename} introuvable. En attente...")
    while not os.path.exists(filename):
      time.sleep(2)

  with open(filename, "r") as f:
    f.seek(0, 2)
    while True:
      line = f.readline()
      if not line:
        time.sleep(0.5)
        continue
      yield line


@app.route("/")
def index():
  return render_template("index.html")


@app.route("/stream")
def stream():
  def event_stream():
    for line in tail_log(LOG_FILE):
      ip_match = IP_REGEX.search(line)
      if ip_match:
        ip = ip_match.group(1)
        geo_data = get_geoip(ip)
        if geo_data:
          ip_counts[ip] += 1
          url = extract_url(line)
          if url:
            url_counts[url] += 1

          payload = {
              "marker": geo_data,
              "top_ips": build_top_ips(10),
              "top_urls": build_top_urls(5),
          }
          yield f"data: {json.dumps(payload)}\n\n"

  return Response(event_stream(), mimetype="text/event-stream")


if __name__ == "__main__":
  app.run(host="0.0.0.0", port=5000, threaded=True)
