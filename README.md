# Ejemplos de uso
## Genera informe_cabeceras.json + informe_cabeceras.txt
python3 cabeceras_server.py analizar https://ejemplo.com

## Con otro nombre de fichero
python3 cabeceras_server.py analizar https://ejemplo.com -o analisis_miweb

## Servidor: genera peticiones_capturadas.jsonl + peticiones_capturadas.txt
python3 cabeceras_server.py server

## Servidor con otro nombre y puerto
python3 cabeceras_server.py server -p 9090 -f captura_test
