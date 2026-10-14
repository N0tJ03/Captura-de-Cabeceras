# cabeceras_server.py

Herramienta de línea de comandos en Python con dos funciones independientes:

1. **Analizador de cabeceras de seguridad**: consulta una URL, revisa las cabeceras HTTP de la respuesta, las cookies y el certificado TLS, y genera un resumen de hallazgos (exportable a JSON y/o TXT).
2. **Servidor HTTP de captura**: levanta un servidor local que registra cada petición recibida (IP, cabeceras, User-Agent, query string, body...) en un fichero de log.

---

## Índice

- [Requisitos](#requisitos)
- [Instalación](#instalación)
- [Uso general](#uso-general)
- [Modo `analizar`](#modo-analizar)
- [Modo `server`](#modo-server)
- [Formato de los ficheros de salida](#formato-de-los-ficheros-de-salida)
- [Limitaciones conocidas](#limitaciones-conocidas)
- [Aviso legal y uso responsable](#aviso-legal-y-uso-responsable)

---

## Requisitos

- Python **3.10 o superior** (el script usa anotaciones de tipo como `dict | None`).
- Librería [`requests`](https://pypi.org/project/requests/).

El resto de módulos (`ssl`, `socket`, `http.server`, `argparse`, `json`...) forman parte de la librería estándar.

## Instalación

```bash
git clone https://github.com/<tu-usuario>/<tu-repositorio>.git
cd <tu-repositorio>
pip install requests
```

## Uso general

El script funciona mediante **subcomandos**:

```bash
python3 cabeceras_server.py <modo> [opciones]
```

| Modo | Descripción |
|------|-------------|
| `analizar` | Analiza las cabeceras de seguridad de una URL |
| `server`   | Inicia el servidor local de captura de peticiones |

Ayuda integrada:

```bash
python3 cabeceras_server.py -h
python3 cabeceras_server.py analizar -h
python3 cabeceras_server.py server -h
```

---

## Modo `analizar`

Realiza una petición `GET` a la URL indicada (siguiendo redirecciones, con timeout de 10 s y un User-Agent de navegador Chrome) y analiza la respuesta.

### Sintaxis

```bash
python3 cabeceras_server.py analizar <url> [-e {json,txt,both,none}] [-o NOMBRE]
```

### Opciones

| Opción | Corto | Por defecto | Descripción |
|--------|-------|-------------|-------------|
| `url` | — | *(obligatorio)* | URL a analizar, con esquema (`http://` o `https://`). |
| `--export` | `-e` | `none` | Formato de exportación del informe: `json`, `txt`, `both` (ambos) o `none` (solo consola). |
| `--output` | `-o` | `informe_cabeceras` | Nombre **base** del fichero de salida. La extensión (`.json` / `.txt`) se añade automáticamente. |

### Ejemplos

```bash
# Solo mostrar el resultado por consola
python3 cabeceras_server.py analizar https://example.com

# Exportar a JSON
python3 cabeceras_server.py analizar https://example.com -e json

# Exportar a JSON y TXT con nombre personalizado
python3 cabeceras_server.py analizar https://example.com -e both -o informe_example
# -> informe_example.json y informe_example.txt
```

### Qué comprueba

**Cabeceras de seguridad** (informa de cuáles están presentes y cuáles faltan):

| Cabecera | Propósito |
|----------|-----------|
| `Strict-Transport-Security` | Fuerza HTTPS (HSTS) |
| `Content-Security-Policy` | Mitiga XSS e inyección de contenido |
| `X-Frame-Options` | Protege contra clickjacking |
| `X-Content-Type-Options` | Evita el sniffing de MIME |
| `Referrer-Policy` | Controla la fuga de información en el referrer |
| `Permissions-Policy` | Restringe APIs del navegador |
| `X-XSS-Protection` | Obsoleta (legacy) |
| `Set-Cookie` | Cookies de sesión |
| `Cross-Origin-Opener-Policy` | Aislamiento cross-origin |
| `Cross-Origin-Resource-Policy` | Aislamiento de recursos |
| `Cross-Origin-Embedder-Policy` | Aislamiento de contenido embebido |

**Comprobaciones adicionales:**

- **HSTS**: detecta `max-age=0` (deshabilitado) y la ausencia de `includeSubDomains`.
- **CSP débil**: avisa si la política contiene `unsafe-inline`, `unsafe-eval`, `*` o `data:`.
- **Clickjacking**: avisa si no existe ni `X-Frame-Options` ni la directiva `frame-ancestors` en la CSP.
- **Cookies**: analiza los flags `Secure`, `HttpOnly` y `SameSite`, y marca las cookies que parecen de sesión (nombre que contiene `sess`, `sid`, `token` o `auth`) si les faltan.
- **Fuga de información**: detecta cabeceras que revelan tecnología (`Server`, `X-Powered-By`, `X-AspNet-Version`, `X-Generator`).
- **Redirecciones**: muestra la cadena de redirecciones y la URL final.
- **TLS**: obtiene sujeto, emisor, fecha de vencimiento y SAN del certificado (puerto 443 del host final).

### Salida por consola (ejemplo)

```
[+] Analizando cabeceras de seguridad de https://example.com

    Estado: 200 | HTTP/11

--- Cabeceras de seguridad ---
    [+] Strict-Transport-Security: max-age=31536000
    [!] Content-Security-Policy: NO presente (Mitiga XSS e inyección de contenido)
    ...

--- TLS ---
    Emisor: Let's Encrypt
    Vence: Dec 31 23:59:59 2026 GMT

--- Resumen de hallazgos ---
    [~] HSTS sin includeSubDomains
    [~] Falta Content-Security-Policy (Mitiga XSS e inyección de contenido)
```

Leyenda: `[+]` presente · `[!]` ausente · `[~]` hallazgo del resumen · `[-]` error.

---

## Modo `server`

Inicia un servidor HTTP multihilo que **responde 200 a cualquier petición** y guarda toda la información recibida. Es útil para depurar webhooks, inspeccionar qué envía un cliente, probar callbacks o analizar tráfico en un laboratorio propio.

### Sintaxis

```bash
python3 cabeceras_server.py server [-p PUERTO] [-f FICHERO] [-r HTML]
```

### Opciones

| Opción | Corto | Por defecto | Descripción |
|--------|-------|-------------|-------------|
| `--puerto` | `-p` | `8080` | Puerto en el que escucha el servidor (se enlaza a `0.0.0.0`, es decir, todas las interfaces). |
| `--file` | `-f` | `peticiones_capturadas.jsonl` | Fichero de log. Si termina en `.jsonl` se guarda en formato JSON Lines; con cualquier otra extensión se usa formato texto plano. |
| `--response` | `-r` | *(respuesta por defecto)* | Fichero HTML que se servirá como respuesta a todas las peticiones. Si no se indica, se sirve una página mínima. |

### Ejemplos

```bash
# Servidor con valores por defecto (puerto 8080, log en JSONL)
python3 cabeceras_server.py server

# Puerto 9000 y log en texto plano
python3 cabeceras_server.py server -p 9000 -f capturas.txt

# Servir una página HTML personalizada
python3 cabeceras_server.py server -p 8080 -r mi_pagina.html
```

Para probarlo desde otra terminal:

```bash
curl -X POST "http://localhost:8080/test?a=1" -d "hola=mundo"
```

Para detenerlo, pulsa `Ctrl+C`.

### Qué registra de cada petición

| Campo | Contenido |
|-------|-----------|
| `timestamp` | Fecha y hora UTC (ISO 8601) |
| `ip` / `puerto` | Dirección y puerto de origen del cliente |
| `metodo` | Método HTTP |
| `path` / `query` | Ruta y query string por separado |
| `user_agent` | Cabecera `User-Agent` |
| `referer` | Cabecera `Referer` |
| `content_type` / `content_length` | Tipo y tamaño declarado del body |
| `headers` | Todas las cabeceras de la petición |
| `body` | Cuerpo de la petición (máximo **64 KB**) |

Métodos soportados: `GET`, `POST`, `PUT`, `DELETE`, `HEAD` y `OPTIONS`.

> **Nota:** si el servidor está detrás de un proxy o balanceador, `ip` mostrará la IP del proxy, no la del cliente final. El script no interpreta `X-Forwarded-For`, aunque esa cabecera quedará guardada en `headers`.

---

## Formato de los ficheros de salida

### Informe del analizador (`.json`)

```json
{
  "url_final": "https://example.com/",
  "fecha_analisis": "2026-10-14T10:00:00+00:00",
  "codigo_estado": 200,
  "version_http": 11,
  "redirecciones": [],
  "cabeceras_respuesta": { "...": "..." },
  "cabeceras_fuga_info": { "Server": "nginx" },
  "cabeceras_seguridad": { "Strict-Transport-Security": "max-age=31536000" },
  "cookies": [],
  "csp_debil": [],
  "tls": { "sujeto": {}, "emisor": {}, "vence": "...", "san": [] },
  "resumen": ["Falta Content-Security-Policy (...)"]
}
```

El informe `.txt` contiene una versión legible con estado, URL final, cabeceras de respuesta y resumen de hallazgos.

### Log del servidor

**JSONL** (por defecto): un objeto JSON por línea.

```json
{"timestamp": "2026-10-14T10:00:00+00:00", "ip": "127.0.0.1", "puerto": 52311, "metodo": "POST", "path": "/test", "query": "a=1", "user_agent": "curl/8.5.0", "headers": {"...": "..."}, "body": "hola=mundo"}
```

**Texto plano** (cualquier otra extensión): una línea por petición.

```
2026-10-14T10:00:00+00:00 | 127.0.0.1:52311 | POST /test | UA: curl/8.5.0 | Headers: {...} | Body: hola=mundo
```

---

## Limitaciones conocidas

- **Cookies múltiples**: `requests` unifica varias cabeceras `Set-Cookie` en una sola, por lo que el análisis de cookies puede ser incompleto cuando el sitio establece más de una.
- **TLS**: solo se consulta el puerto 443 del host de la URL final; si la URL usa otro puerto, el dato TLS puede no corresponder.
- **Análisis puntual**: solo se analiza una URL y una única petición `GET`; no se rastrean otras rutas del sitio.
- **Servidor sin HTTPS ni autenticación**: el servidor de captura sirve HTTP en claro y acepta cualquier petición.

## Aviso legal y uso responsable

- Utiliza el **analizador** únicamente sobre sitios propios o sobre los que tengas autorización para realizar pruebas.
- El **servidor** escucha en todas las interfaces (`0.0.0.0`) y guarda IPs, cabeceras y cuerpos de petición, que pueden contener datos personales o credenciales. Si lo expones a Internet, asegúrate de cumplir la normativa aplicable en materia de protección de datos (por ejemplo, RGPD), informa a los usuarios cuando corresponda y protege adecuadamente los ficheros de log.
- Los autores no se hacen responsables del uso indebido de esta herramienta.

## Licencia

Añade aquí la licencia de tu proyecto (por ejemplo, MIT).
