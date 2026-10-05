#!/usr/bin/env python3
"""
Prepara el inventario de clientes para los avisos por correo. SE EJECUTA EN TU PC.

Lee tu Excel (columnas: Cliente | Fabricante | Producto | Versión) y lo separa en dos partes:
  - Inventario con alias: alias, fabricante, producto, versión (sin nombres de cliente).
  - Tabla de nombres: alias -> nombre real del cliente.
Las dos se guardan como secretos de GitHub (INVENTARIO_CLIENTES y CLIENTES_NOMBRES). Los alias se
recuerdan en .alias_clientes.json para que cada cliente conserve siempre el mismo.

Este script nunca muestra nombres de clientes por pantalla.

Uso:
  python preparar_inventario.py clientes.xlsx                 # comprueba el Excel, no sube nada
  python preparar_inventario.py clientes.xlsx --subir         # además guarda los secretos en GitHub
  python preparar_inventario.py clientes.xlsx --exportar-alias inventario_alias.csv
                                                              # CSV sin nombres (alias, fabricante, producto, versión)

Requiere: pip install openpyxl   (y GitHub CLI con sesión iniciada para --subir)
"""
import argparse
import csv
import json
import os
import shutil
import subprocess
import sys
import unicodedata

import afectacion

REPO = "JanPrats/informe-vulns"
CARPETA = os.path.dirname(os.path.abspath(__file__))
RUTA_ALIAS = os.path.join(CARPETA, ".alias_clientes.json")
COLUMNAS = {"cliente": "cliente", "fabricante": "fabricante", "producto": "producto",
            "version": "version", "versión": "version"}
GH_RUTAS = [r"C:\Users\jprats\AppData\Local\Microsoft\WinGet\Packages\GitHub.cli_Microsoft.Winget.Source_8wekyb3d8bbwe\bin\gh.exe"]


def _clave(t):
    t = unicodedata.normalize("NFD", str(t or "")).encode("ascii", "ignore").decode().strip().lower()
    return t


def leer_excel(ruta):
    import openpyxl
    libro = openpyxl.load_workbook(ruta, read_only=True, data_only=True)
    hoja = libro.worksheets[0]
    filas = list(hoja.iter_rows(values_only=True))
    if not filas:
        sys.exit("El Excel está vacío.")
    cabecera = [_clave(c) for c in filas[0]]
    indices = {}
    for i, c in enumerate(cabecera):
        if c in COLUMNAS:
            indices[COLUMNAS[c] if c != "versión" else "version"] = i
    faltan = {"cliente", "fabricante", "producto", "version"} - set(indices)
    if faltan:
        sys.exit(f"Faltan columnas en el Excel: {', '.join(sorted(faltan))}. "
                 "La primera fila debe ser: Cliente | Fabricante | Producto | Versión")
    equipos, avisos = [], 0
    for n, fila in enumerate(filas[1:], start=2):
        valores = {k: ("" if fila[i] is None else str(fila[i]).strip()) for k, i in indices.items()}
        if not any(valores.values()):
            continue
        if not all(valores[k] for k in ("cliente", "fabricante", "producto", "version")):
            avisos += 1
            print(f"  ! Fila {n}: falta algún dato (se omite)", file=sys.stderr)
            continue
        equipos.append(valores)
    return equipos, avisos


def asignar_alias(equipos):
    """Cada cliente recibe un alias estable (CLI-001…). Los ya asignados se conservan entre ejecuciones."""
    try:
        with open(RUTA_ALIAS, encoding="utf-8") as f:
            alias = json.load(f)
    except (OSError, ValueError):
        alias = {}
    siguiente = max([int(a.split("-")[1]) for a in alias.values()] or [0]) + 1
    for e in equipos:
        if e["cliente"] not in alias:
            alias[e["cliente"]] = f"CLI-{siguiente:03d}"
            siguiente += 1
    with open(RUTA_ALIAS, "w", encoding="utf-8") as f:
        json.dump(alias, f, ensure_ascii=False, indent=1)
    inventario = [{"alias": alias[e["cliente"]], "fabricante": e["fabricante"], "producto": e["producto"],
                   "version": e["version"]} for e in equipos]
    nombres = {alias[c]: c for c in {e["cliente"] for e in equipos}}
    return inventario, nombres


def gh():
    for r in GH_RUTAS + [shutil.which("gh") or ""]:
        if r and os.path.exists(r):
            return r
    sys.exit("No encuentro GitHub CLI (gh). Instálalo o añade su ruta en GH_RUTAS.")


def subir_secreto(nombre, valor):
    r = subprocess.run([gh(), "secret", "set", nombre, "-R", REPO], input=valor, text=True,
                       capture_output=True)
    if r.returncode != 0:
        sys.exit(f"No se pudo guardar el secreto {nombre}: {r.stderr.strip()}")


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    p = argparse.ArgumentParser(description="Prepara el inventario de clientes (sin exponer sus nombres)")
    p.add_argument("excel", help="Excel con columnas Cliente | Fabricante | Producto | Versión")
    p.add_argument("--subir", action="store_true", help="guarda el inventario y los nombres como secretos de GitHub")
    p.add_argument("--exportar-alias", metavar="CSV", help="guarda un CSV sin nombres (alias, fabricante, producto, versión)")
    a = p.parse_args()

    equipos, omitidas = leer_excel(a.excel)
    inventario, nombres = asignar_alias(equipos)
    fabricantes = sorted({e["fabricante"] for e in inventario})
    print(f"Leídos {len(inventario)} equipos de {len(nombres)} clientes ({omitidas} filas omitidas).")
    print(f"Fabricantes: {', '.join(fabricantes)}")

    paquete_inv, paquete_nom = afectacion.empaquetar(inventario), afectacion.empaquetar(nombres)
    for nombre, paquete in (("INVENTARIO_CLIENTES", paquete_inv), ("CLIENTES_NOMBRES", paquete_nom)):
        if len(paquete) > 48000:
            sys.exit(f"{nombre} ocupa {len(paquete)} bytes: supera el máximo de un secreto de GitHub (48 KB).")

    if a.exportar_alias:
        with open(a.exportar_alias, "w", newline="", encoding="utf-8-sig") as f:
            w = csv.DictWriter(f, fieldnames=["alias", "fabricante", "producto", "version"], delimiter=";")
            w.writeheader()
            w.writerows(inventario)
        print(f"CSV sin nombres guardado en {a.exportar_alias}")

    if a.subir:
        subir_secreto("INVENTARIO_CLIENTES", paquete_inv)
        subir_secreto("CLIENTES_NOMBRES", paquete_nom)
        print("Secretos INVENTARIO_CLIENTES y CLIENTES_NOMBRES guardados en GitHub.")
    else:
        print("No se ha subido nada (usa --subir para guardar los secretos en GitHub).")


if __name__ == "__main__":
    main()
