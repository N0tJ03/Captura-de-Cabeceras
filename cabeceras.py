#!/usr/bin/env python3
# cabeceras_server.py
# Parte 1: Analiza cabeceras de seguridad de un sitio y exporta el resultado (JSON/TXT).
# Parte 2: Servidor HTTP local que registra peticiones completas (IP, headers, UA, body...).
# Requiere: pip install requests

import sys
import json
import threading
import ssl
import socket
import argparse
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

try:
    import requests
except ImportError:
    print("[-] Falta 'requests'. Instala con: pip install requests")
    sys.exit(1)

# ------------------------------ PARTE 1 ------------------------------

CABECERAS_SEGURIDAD = {
    "Strict-Transport-Security": "Fuerza HTTPS (HSTS)",
    "Content-Security-Policy": "Mitiga XSS e inyección de contenido",
    "X-Frame-Options": "Protege contra clickjacking",
    "X-Content-Type-Options": "Evita sniffing de MIME",
    "Referrer-Policy": "Controla fuga de referrer",
    "Permissions-Policy": "Restringe APIs del navegador",
    "X-XSS-Protection": "Obsoleto (legacy)",
    "Set-Cookie": "Cookies de sesión",
    "Cross-Origin-Opener-Policy": "Aislamiento cross-origin",
    "Cross-Origin-Resource-Policy": "Aislamiento de recursos",
    "Cross-Origin-Embedder-Policy": "Aislamiento de embebidos",
}

CABECERAS_FUGA = ["Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"]

# Políticas CSP consideradas débiles si están presentes
CSP_DEBIL = ["unsafe-inline", "unsafe-eval", "*", "data:"]

UA_NAVEGADOR = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"


def analizar_cookie(valor: str) -> dict:
    """Extrae flags de seguridad de una cookie Set-Cookie."""
    partes = [p.strip().lower() for p in valor.split(";")]
    return {
        "nombre": valor.split("=", 1)[0].strip(),
        "secure": "secure" in partes,
        "httponly": "httponly" in partes,
        "samesite": next((p.split("=", 1)[1] for p in partes if p.startswith("samesite")), None),
        "session": any(k in partes[0].lower() for k in ("sess", "sid", "token", "auth")),
    }


def info_tls(host: str, puerto: int = 443) -> dict | None:
    """Devuelve datos básicos del certificado TLS."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, puerto), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as s:
                cert = s.getpeercert()
                return {
                    "sujeto": dict(x[0] for x in cert.get("subject", [])),
                    "emisor": dict(x[0] for x in cert.get("issuer", [])),
                    "vence": cert.get("notAfter"),
                    "san": list(cert.get("subjectAltName", [])),
                }
    except Exception:
        return None


def analizar_cabeceras(url: str, export: str = "none", fichero: str = None) -> dict | None:
    print(f"\n[+] Analizando cabeceras de seguridad de {url}\n")
    try:
        r = requests.get(url, timeout=10, headers={"User-Agent": UA_NAVEGADOR},
                         allow_redirects=True)
    except requests.RequestException as e:
        print(f"[-] Error en la petición: {e}")
        return None

    headers = dict(r.headers)
    informe = {
        "url_final": r.url,
        "fecha_analisis": datetime.now(timezone.utc).isoformat(),
        "codigo_estado": r.status_code,
        "version_http": r.raw.version if hasattr(r.raw, "version") else None,
        "redirecciones": [h.get("Location") for h in r.history],
        "cabeceras_respuesta": headers,
        "cabeceras_fuga_info": {k: headers[k] for k in CABECERAS_FUGA if k in headers},
        "cabeceras_seguridad": {},
        "cookies": [],
        "csp_debil": [],
        "tls": None,
        "resumen": [],
    }

    print(f"    Estado: {r.status_code} | HTTP/{informe['version_http']}")
    if r.history:
        print(f"    Redirecciones: {' -> '.join(str(h.status_code) for h in r.history)} -> {r.url}")

    print("\n--- Cabeceras de seguridad ---")
    for cab, desc in CABECERAS_SEGURIDAD.items():
        valor = headers.get(cab)
        if valor:
            informe["cabeceras_seguridad"][cab] = valor
            print(f"    [+] {cab}: {valor}")
            if cab == "Strict-Transport-Security":
                if "max-age=0" in valor.lower():
                    informe["resumen"].append("HSTS con max-age=0 (deshabilitado)")
                elif "includesubdomains" not in valor.lower():
                    informe["resumen"].append("HSTS sin includeSubDomains")
            if cab == "Content-Security-Policy":
                debiles = [p for p in CSP_DEBIL if p in valor]
                if debiles:
                    informe["csp_debil"] = debiles
                    informe["resumen"].append(f"CSP con directivas débiles: {', '.join(debiles)}")
        else:
            informe["resumen"].append(f"Falta {cab} ({desc})")
            print(f"    [!] {cab}: NO presente ({desc})")

    if "X-Frame-Options" not in headers and "frame-ancestors" not in headers.get("Content-Security-Policy", ""):
        informe["resumen"].append("Sin protección contra clickjacking (ni XFO ni CSP frame-ancestors)")

    cookies_raw = headers.get("Set-Cookie", "")
    if cookies_raw:
        for c in r.headers.get("Set-Cookie", "").split("\n") or [cookies_raw]:
            informe["cookies"].append(analizar_cookie(c))
    for c in informe["cookies"]:
        faltan = [f for f in ("secure", "httponly") if not c[f]] + ([] if c["samesite"] else ["samesite"])
        if faltan and c["session"]:
            informe["resumen"].append(f"Cookie '{c['nombre']}' sin: {', '.join(faltan)}")

    if informe["cabeceras_fuga_info"]:
        informe["resumen"].append(f"Cabeceras que revelan tecnología: {', '.join(informe['cabeceras_fuga_info'])}")

    from urllib.parse import urlparse
    host = urlparse(r.url).hostname
    if host:
        informe["tls"] = info_tls(host)
        if informe["tls"]:
            print(f"\n--- TLS ---\n    Emisor: {informe['tls']['emisor'].get('organizationName', '?')}")
            print(f"    Vence: {informe['tls']['vence']}")

    print("\n--- Todas las cabeceras de respuesta ---")
    for k, v in headers.items():
        print(f"    {k}: {v}")

    print("\n--- Resumen de hallazgos ---")
    for hallazgo in informe["resumen"]:
        print(f"    [~] {hallazgo}")

    if export in ("json", "both") and fichero:
        with open(fichero + ".json", "w", encoding="utf-8") as f:
            json.dump(informe, f, indent=2, ensure_ascii=False)
        print(f"\n[+] Informe JSON guardado en {fichero}.json")
    if export in ("txt", "both") and fichero:
        with open(fichero + ".txt", "w", encoding="utf-8") as f:
            f.write(f"INFORME DE CABECERAS - {url}\n{informe['fecha_analisis']}\n\n")
            f.write(f"Estado: {informe['codigo_estado']}\nURL final: {informe['url_final']}\n\n")
            f.write("== Cabeceras de respuesta ==\n")
            for k, v in headers.items():
                f.write(f"{k}: {v}\n")
            f.write("\n== Resumen ==\n")
            for h in informe["resumen"]:
                f.write(f"- {h}\n")
        print(f"[+] Informe TXT guardado en {fichero}.txt")

    return informe


# ------------------------------ PARTE 2 ------------------------------

class Registro:
    def __init__(self, fichero, formato="jsonl"):
        self.fichero = fichero
        self.formato = formato
        self.lock = threading.Lock()

    def guardar(self, entrada: dict):
        with self.lock:
            if self.formato == "jsonl":
                with open(self.fichero, "a", encoding="utf-8") as f:
                    f.write(json.dumps(entrada, ensure_ascii=False) + "\n")
            else:
                with open(self.fichero, "a", encoding="utf-8") as f:
                    f.write(
                        f"{entrada['timestamp']} | {entrada['ip']}:{entrada['puerto']} | "
                        f"{entrada['metodo']} {entrada['path']} | UA: {entrada['user_agent']} | "
                        f"Headers: {json.dumps(entrada['headers'], ensure_ascii=False)} | "
                        f"Body: {entrada['body']}\n"
                    )


REGISTRO = None
RESPUESTA_HTML = b"<html><body><h1>Servidor de captura</h1></body></html>"


class Manejador(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _procesar(self):
        longitud = int(self.headers.get("Content-Length", 0) or 0)
        body = ""
        if longitud:
            raw = self.rfile.read(min(longitud, 64 * 1024))  # límite 64KB
            body = raw.decode("utf-8", errors="replace")

        entrada = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "ip": self.client_address[0],
            "puerto": self.client_address[1],
            "metodo": self.command,
            "path": self.path.split("?", 1)[0],
            "query": self.path.split("?", 1)[1] if "?" in self.path else None,
            "user_agent": self.headers.get("User-Agent", "desconocido"),
            "referer": self.headers.get("Referer"),
            "content_type": self.headers.get("Content-Type"),
            "content_length": longitud,
            "headers": dict(self.headers.items()),
            "body": body,
        }

        print(f"\n[CAPTURA] {entrada['metodo']} {self.path} desde {entrada['ip']}")
        print(f"[CAPTURA] User-Agent: {entrada['user_agent']}")
        if body:
            print(f"[CAPTURA] Body ({len(body)} bytes): {body[:200]}")

        REGISTRO.guardar(entrada)

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(RESPUESTA_HTML)))
        self.end_headers()
        self.wfile.write(RESPUESTA_HTML)

    do_GET = _procesar
    do_POST = _procesar
    do_PUT = _procesar
    do_DELETE = _procesar
    do_HEAD = _procesar
    do_OPTIONS = _procesar

    def log_message(self, *args):
        pass


def servidor(puerto=8080, fichero="peticiones_capturadas.jsonl", respuesta=None):
    global REGISTRO, RESPUESTA_HTML
    if respuesta:
        with open(respuesta, "rb") as f:
            RESPUESTA_HTML = f.read()

    REGISTRO = Registro(fichero, "jsonl" if fichero.endswith(".jsonl") else "txt")
    print(f"\n[+] Servidor HTTP escuchando en 0.0.0.0:{puerto}")
    print(f"[+] Log: {fichero} | Sirviendo respuesta personalizada" if respuesta else f"[+] Log: {fichero}")
    print("[+] Ctrl+C para salir\n")

    httpd = ThreadingHTTPServer(("0.0.0.0", puerto), Manejador)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[+] Servidor detenido.")
    finally:
        httpd.server_close()


# ------------------------------ CLI ------------------------------

def main():
    p = argparse.ArgumentParser(
        prog="cabeceras_server.py",
        description="Análisis de cabeceras de seguridad + servidor de captura de peticiones.",
    )
    sub = p.add_subparsers(dest="modo", required=True)

    a1 = sub.add_parser("analizar", help="analizar cabeceras de seguridad de una URL")
    a1.add_argument("url", help="URL a analizar (http(s)://...)")
    a1.add_argument("-e", "--export", choices=["json", "txt", "both", "none"], default="none")
    a1.add_argument("-o", "--output", default="informe_cabeceras", help="nombre base del fichero de salida")

    a2 = sub.add_parser("server", help="iniciar servidor de captura")
    a2.add_argument("-p", "--puerto", type=int, default=8080)
    a2.add_argument("-f", "--file", default="peticiones_capturadas.jsonl")
    a2.add_argument("-r", "--response", help="fichero HTML a servir como respuesta")

    args = p.parse_args()

    if args.modo == "analizar":
        analizar_cabeceras(args.url, args.export, args.output)
    else:
        servidor(args.puerto, args.file, args.response)


if __name__ == "__main__":
    main()
