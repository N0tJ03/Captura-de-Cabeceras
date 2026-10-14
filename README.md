Herramienta de auditoría HTTP en Python con dos modos de funcionamiento:

analizar — Analiza las cabeceras de seguridad de una URL y genera un informe en JSON y TXT.
server — Lanza un servidor HTTP local que captura y registra todas las peticiones que recibe (IP, headers, User-Agent, body...) en JSONL y TXT.
Útil en auditorías web autorizadas: verificar configuración de cabeceras de seguridad, detección de cabeceras que filtran tecnología, y análisis de peticiones de clientes (fingerprinting de User-Agents, debugging de peticiones, etc.).

Requisitos
Python 3.8 o superior
requests
bash



pip install requests
Instalación
Guarda el script y dale permisos de ejecución (opcional):

bash



chmod +x cabeceras_server.py
Uso general
bash



python3 cabeceras_server.py <modo> [opciones]
text



usage: cabeceras_server.py [-h] {analizar,server} ...
Modo 1: analizar
Analiza las cabeceras de seguridad de una URL y guarda el informe siempre en dos ficheros: .json y .txt.

bash



python3 cabeceras_server.py analizar <URL> [opciones]
Opciones


Opción	Por defecto	Descripción
url (posicional)	—	URL a analizar (con http:// o https://)
-o, --output	informe_cabeceras	Nombre base de salida. Genera <nombre>.json y <nombre>.txt
Ejemplos
bash



# Análisis básico (genera informe_cabeceras.json + informe_cabeceras.txt)
python3 cabeceras_server.py analizar https://ejemplo.com

# Con nombre de fichero personalizado
python3 cabeceras_server.py analizar https://ejemplo.com -o auditoria_miweb
Qué analiza
Cabeceras de seguridad (presencia y contenido):
Strict-Transport-Security (HSTS) — incluye detección de max-age=0 y falta de includeSubDomains
Content-Security-Policy — detecta directivas débiles (unsafe-inline, unsafe-eval, *, data:)
X-Frame-Options / frame-ancestors — protección contra clickjacking
X-Content-Type-Options
Referrer-Policy
Permissions-Policy
X-XSS-Protection (legacy)
Cross-Origin-Opener-Policy, Cross-Origin-Resource-Policy, Cross-Origin-Embedder-Policy
Set-Cookie
Cookies: flags Secure, HttpOnly, SameSite y si parecen cookies de sesión.
Cabeceras que revelan tecnología: Server, X-Powered-By, X-AspNet-Version, X-Generator.
TLS: emisor del certificado, fecha de caducidad y SANs.
General: código de estado, versión HTTP, cadena de redirecciones, todas las cabeceras de respuesta.
Resumen de hallazgos: lista de puntos débiles detectados, incluida la ausencia de protección contra clickjacking (XFO + CSP frame-ancestors).
Formato de salida
.json: informe completo estructurado (ideal para automatización, diffing entre análisis o integrar en otros scripts).
.txt: informe legible con secciones: cabeceras de respuesta, cabeceras de seguridad presentes/ausentes, cookies, TLS y resumen de hallazgos.
Modo 2: server
Lanza un servidor HTTP local (por defecto en 0.0.0.0:8080) que registra cada petición que recibe y responde con una página HTML simple.

bash



python3 cabeceras_server.py server [opciones]
Opciones


Opción	Por defecto	Descripción
-p, --puerto	8080	Puerto de escucha
-f, --file	peticiones_capturadas	Nombre base de los logs. Genera <nombre>.jsonl y <nombre>.txt
-r, --response	—	Fichero HTML personalizado a servir como respuesta
Ejemplos
bash



# Servidor básico en puerto 8080
python3 cabeceras_server.py server

# Puerto y ficheros personalizados
python3 cabeceras_server.py server -p 9090 -f captura_test

# Servir una página HTML concreta
python3 cabeceras_server.py server -p 8080 -r pagina.html
Qué captura de cada petición
Fecha/hora UTC
IP y puerto de origen
Método HTTP (GET, POST, PUT, DELETE, HEAD, OPTIONS...)
Path y query string por separado
User-Agent
Referer
Content-Type y Content-Length
Todos los headers de la petición
Cuerpo (body) de las peticiones con datos (limitado a 64 KB por seguridad)
Formato de salida
.jsonl: un objeto JSON por línea (fácil de procesar con jq o Python):
bash



cat peticiones_capturadas.jsonl | jq
cat peticiones_capturadas.jsonl | jq 'select(.user_agent | contains("curl"))'
.txt: una línea legible por petición, con todos los campos concatenados.
El servidor es multihilo (ThreadingHTTPServer), soporta peticiones concurrentes y se detiene con Ctrl+C.
