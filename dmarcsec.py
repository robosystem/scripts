#!/usr/bin/env python3
"""
DMARC XML Report Analyzer + AbuseIPDB Lookup
Analizza file XML di report DMARC, estrae gli IP con SPF auth = "fail"
e li verifica tramite l'API di AbuseIPDB.

Uso:
    python dmarc_abuseipdb.py <cartella_xml> --api-key <ABUSEIPDB_API_KEY>

Opzioni:
    -k, --api-key       API key di AbuseIPDB (oppure variabile d'ambiente ABUSEIPDB_API_KEY)
    -m, --max-age-days  Numero di giorni per il lookup AbuseIPDB (default: 90)
    -o, --output        File CSV di output con i risultati (opzionale)
    -v, --verbose       Mostra dettagli aggiuntivi durante l'elaborazione
    -d, --delay         Secondi di attesa tra chiamate API (default: 1.0)
    -r, --remove        Elimina i file XML dopo l'analisi
    -l, --log           Accoda i record SPF-fail a 'analisi.log' nella cartella corrente
"""

import os
import sys
import gzip
import shutil
import tarfile
import zipfile
import argparse
import xml.etree.ElementTree as ET
import requests
import json
import csv
import time
from datetime import datetime, timezone
from pathlib import Path
from collections import defaultdict


# ──────────────────────────────────────────────
# Decompressione archivi
# ──────────────────────────────────────────────

def estrai_archivi(folder: Path, verbose: bool = False):
    """
    Equivalente Python di rexplode: estrae tutti gli archivi presenti
    nella cartella target e rimuove i file sorgente dopo l'estrazione.
    Gestisce: .tar.gz / .tgz, .tar, .zip, .gz (singolo file).
    """

    def _rimuovi(path: Path):
        try:
            path.unlink()
            if verbose:
                print(f"  [arch] Rimosso archivio: {path.name}")
        except OSError as e:
            print(f"  [!] Impossibile rimuovere '{path.name}': {e}")

    # .tar.gz e .tgz
    for arch in list(folder.rglob("*.tar.gz")) + list(folder.rglob("*.tgz")):
        if arch.name.startswith("._"):
            continue
        try:
            with tarfile.open(arch, "r:gz") as tf:
                tf.extractall(path=arch.parent)
            if verbose:
                print(f"  [arch] Estratto: {arch.name}")
            _rimuovi(arch)
        except Exception as e:
            print(f"  [!] Errore estrazione '{arch.name}': {e}")

    # .tar
    for arch in folder.rglob("*.tar"):
        if arch.name.startswith("._"):
            continue
        try:
            with tarfile.open(arch, "r:") as tf:
                tf.extractall(path=arch.parent)
            if verbose:
                print(f"  [arch] Estratto: {arch.name}")
            _rimuovi(arch)
        except Exception as e:
            print(f"  [!] Errore estrazione '{arch.name}': {e}")

    # .zip
    for arch in folder.rglob("*.zip"):
        if arch.name.startswith("._"):
            continue
        try:
            with zipfile.ZipFile(arch, "r") as zf:
                zf.extractall(path=arch.parent)
            if verbose:
                print(f"  [arch] Estratto: {arch.name}")
            _rimuovi(arch)
        except Exception as e:
            print(f"  [!] Errore estrazione '{arch.name}': {e}")

    # .gz singolo file (non .tar.gz)
    for arch in folder.rglob("*.gz"):
        if arch.name.startswith("._") or arch.name.endswith(".tar.gz"):
            continue
        dest = arch.parent / arch.stem  # rimuove .gz dal nome
        try:
            with gzip.open(arch, "rb") as gz_in, open(dest, "wb") as f_out:
                shutil.copyfileobj(gz_in, f_out)
            if verbose:
                print(f"  [arch] Estratto: {arch.name} → {dest.name}")
            _rimuovi(arch)
        except Exception as e:
            print(f"  [!] Errore estrazione '{arch.name}': {e}")


# ──────────────────────────────────────────────
# Parsing DMARC XML
# ──────────────────────────────────────────────

def parse_dmarc_xml(filepath: Path) -> list[dict]:
    """
    Analizza un file XML di report DMARC e restituisce i record
    con SPF auth result = "fail".
    """
    try:
        tree = ET.parse(filepath)
        root = tree.getroot()
    except ET.ParseError as e:
        print(f"  [!] Errore parsing XML '{filepath.name}': {e}")
        return []

    fail_records = []

    # Metadati del report
    report_metadata = root.find("report_metadata")
    policy_domain = ""
    report_id = ""
    date_range_begin = ""
    date_range_end = ""

    if report_metadata is not None:
        org_name_el = report_metadata.find("org_name")
        report_id_el = report_metadata.find("report_id")
        date_begin_el = report_metadata.find("date_range/begin")
        date_end_el = report_metadata.find("date_range/end")

        report_id = report_id_el.text if report_id_el is not None else "N/A"

        if date_begin_el is not None and date_begin_el.text:
            try:
                date_range_begin = datetime.fromtimestamp(
                    int(date_begin_el.text), tz=timezone.utc
                ).strftime("%Y-%m-%d")
            except (ValueError, OSError):
                date_range_begin = date_begin_el.text

        if date_end_el is not None and date_end_el.text:
            try:
                date_range_end = datetime.fromtimestamp(
                    int(date_end_el.text), tz=timezone.utc
                ).strftime("%Y-%m-%d")
            except (ValueError, OSError):
                date_range_end = date_end_el.text

    # Dominio della policy
    policy_published = root.find("policy_published")
    if policy_published is not None:
        domain_el = policy_published.find("domain")
        if domain_el is not None:
            policy_domain = domain_el.text or ""

    # Analisi dei record
    for record in root.findall("record"):
        row = record.find("row")
        if row is None:
            continue

        source_ip_el = row.find("source_ip")
        count_el = row.find("count")
        if source_ip_el is None:
            continue

        source_ip = source_ip_el.text or ""
        count = int(count_el.text) if count_el is not None and count_el.text else 1

        # Controlla auth_results/spf
        auth_results = record.find("auth_results")
        if auth_results is None:
            continue

        for spf in auth_results.findall("spf"):
            spf_result_el = spf.find("result")
            spf_domain_el = spf.find("domain")
            spf_scope_el = spf.find("scope")

            spf_result = spf_result_el.text if spf_result_el is not None else ""
            spf_domain = spf_domain_el.text if spf_domain_el is not None else ""
            spf_scope = spf_scope_el.text if spf_scope_el is not None else ""

            if spf_result and spf_result.lower() == "fail":
                # Recupera anche DMARC disposition
                policy_evaluated = row.find("policy_evaluated")
                dmarc_disposition = ""
                dkim_result = ""
                spf_eval_result = ""
                if policy_evaluated is not None:
                    disp_el = policy_evaluated.find("disposition")
                    dkim_el = policy_evaluated.find("dkim")
                    spf_eval_el = policy_evaluated.find("spf")
                    dmarc_disposition = disp_el.text if disp_el is not None else ""
                    dkim_result = dkim_el.text if dkim_el is not None else ""
                    spf_eval_result = spf_eval_el.text if spf_eval_el is not None else ""

                # Header from (identifiers)
                identifiers = record.find("identifiers")
                header_from = ""
                if identifiers is not None:
                    hf_el = identifiers.find("header_from")
                    header_from = hf_el.text if hf_el is not None else ""

                fail_records.append({
                    "file": filepath.name,
                    "report_id": report_id,
                    "policy_domain": policy_domain,
                    "date_begin": date_range_begin,
                    "date_end": date_range_end,
                    "source_ip": source_ip,
                    "count": count,
                    "spf_domain": spf_domain,
                    "spf_scope": spf_scope,
                    "spf_auth_result": spf_result,
                    "dmarc_disposition": dmarc_disposition,
                    "dkim_eval": dkim_result,
                    "spf_eval": spf_eval_result,
                    "header_from": header_from,
                })

    return fail_records


# ──────────────────────────────────────────────
# AbuseIPDB API
# ──────────────────────────────────────────────

def check_abuseipdb(ip: str, api_key: str, max_age_days: int = 90) -> dict | None:
    """
    Interroga l'API AbuseIPDB per un dato indirizzo IP.
    Restituisce i dati del report o None in caso di errore.
    """
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": api_key,
        "Accept": "application/json",
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": max_age_days,
        "verbose": False,
    }

    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)

        if response.status_code == 200:
            data = response.json().get("data", {})
            return {
                "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                "total_reports": data.get("totalReports", 0),
                "last_reported_at": data.get("lastReportedAt", ""),
                "country_code": data.get("countryCode", ""),
                "isp": data.get("isp", ""),
                "domain": data.get("domain", ""),
                "is_tor": data.get("isTor", False),
                "is_public": data.get("isPublic", True),
                "usage_type": data.get("usageType", ""),
                "num_distinct_users": data.get("numDistinctUsers", 0),
            }
        elif response.status_code == 401:
            print("  [!] API key non valida o non autorizzata.")
            return None
        elif response.status_code == 429:
            print("  [!] Rate limit raggiunto. Attendere...")
            time.sleep(60)
            return check_abuseipdb(ip, api_key, max_age_days)
        elif response.status_code == 422:
            print(f"  [!] IP non valido o non elaborabile: {ip}")
            return None
        else:
            print(f"  [!] Errore API per {ip}: HTTP {response.status_code}")
            return None

    except requests.exceptions.Timeout:
        print(f"  [!] Timeout per IP {ip}")
        return None
    except requests.exceptions.RequestException as e:
        print(f"  [!] Errore di rete per {ip}: {e}")
        return None


# ──────────────────────────────────────────────
# Output e Report
# ──────────────────────────────────────────────

def print_result(record: dict, abuse_data: dict | None):
    """Stampa a schermo il risultato per un IP."""
    ip = record["source_ip"]
    score = abuse_data.get("abuse_confidence_score", "N/A") if abuse_data else "N/A"
    country = abuse_data.get("country_code", "??") if abuse_data else "??"
    isp = abuse_data.get("isp", "N/A") if abuse_data else "N/A"
    reports = abuse_data.get("total_reports", 0) if abuse_data else 0
    last_seen = abuse_data.get("last_reported_at", "mai") if abuse_data else "N/A"

    # Colore in base al punteggio
    if isinstance(score, int):
        if score >= 75:
            risk = "🔴 ALTO RISCHIO"
        elif score >= 25:
            risk = "🟠 RISCHIO MEDIO"
        else:
            risk = "🟢 BASSO RISCHIO"
    else:
        risk = "⚪ N/A"

    print(f"\n  IP:              {ip}")
    print(f"  Dominio DMARC:   {record['policy_domain']} | Header-From: {record['header_from']}")
    print(f"  Periodo:         {record['date_begin']} → {record['date_end']}")
    print(f"  Messaggi (count):{record['count']} | Disposition: {record['dmarc_disposition']}")
    print(f"  AbuseIPDB Score: {score}/100  {risk}")
    print(f"  Paese:           {country} | ISP: {isp}")
    print(f"  Segnalazioni:    {reports} (ultimo: {last_seen})")


def save_csv(results: list[dict], output_path: str):
    """Salva i risultati in un file CSV."""
    if not results:
        return

    fieldnames = [
        "source_ip", "policy_domain", "header_from", "date_begin", "date_end",
        "count", "spf_domain", "spf_scope", "dmarc_disposition", "dkim_eval", "spf_eval",
        "abuse_confidence_score", "total_reports", "last_reported_at",
        "country_code", "isp", "domain", "usage_type", "is_tor",
        "file", "report_id",
    ]

    with open(output_path, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(results)

    print(f"\n✅ Risultati salvati in: {output_path}")


def append_log(records: list[dict], log_path: str = "analisi.log"):
    """
    Accoda al file analisi.log i record SPF-fail con i relativi dati AbuseIPDB.
    Ogni sessione è separata da un'intestazione con timestamp.
    """
    if not records:
        return

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    separator = "─" * 60

    with open(log_path, "a", encoding="utf-8") as f:
        f.write(f"\n{'='*60}\n")
        f.write(f"  Analisi del {now}\n")
        f.write(f"{'='*60}\n")

        for r in records:
            score = r.get("abuse_confidence_score", "N/A")
            if isinstance(score, int):
                if score >= 75:
                    risk = "ALTO RISCHIO"
                elif score >= 25:
                    risk = "RISCHIO MEDIO"
                else:
                    risk = "BASSO RISCHIO"
            else:
                risk = "N/A"

            f.write(f"\n{separator}\n")
            f.write(f"  IP:              {r.get('source_ip', '')}\n")
            f.write(f"  File sorgente:   {r.get('file', '')}  (report: {r.get('report_id', '')})\n")
            f.write(f"  Dominio DMARC:   {r.get('policy_domain', '')} | Header-From: {r.get('header_from', '')}\n")
            f.write(f"  Periodo:         {r.get('date_begin', '')} → {r.get('date_end', '')}\n")
            f.write(f"  Messaggi:        {r.get('count', '')} | Disposition: {r.get('dmarc_disposition', '')}\n")
            f.write(f"  SPF domain:      {r.get('spf_domain', '')} | scope: {r.get('spf_scope', '')}\n")
            f.write(f"  DKIM eval:       {r.get('dkim_eval', '')} | SPF eval: {r.get('spf_eval', '')}\n")
            f.write(f"  AbuseIPDB Score: {score}/100  [{risk}]\n")
            f.write(f"  Paese:           {r.get('country_code', '??')} | ISP: {r.get('isp', 'N/A')}\n")
            f.write(f"  Segnalazioni:    {r.get('total_reports', 0)} (ultimo: {r.get('last_reported_at', 'mai')})\n")
            f.write(f"  Usage type:      {r.get('usage_type', '')} | TOR: {r.get('is_tor', False)}\n")

        f.write(f"\n{'='*60}\n")

    print(f"\n📝 Log accodato in: {log_path}  ({len(records)} record)")


# ──────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Analizza report DMARC XML e verifica gli IP con SPF fail su AbuseIPDB."
    )
    parser.add_argument(
        "folder",
        nargs='?',
        default=Path('.'),
        type=Path,
        help="Cartella contenente i file XML dei report DMARC (default: cartella corrente)",
    )
    parser.add_argument(
        "-k", "--api-key",
        default=os.environ.get("ABUSEIPDB_API_KEY", ""),
        help="API key di AbuseIPDB (o variabile d'ambiente ABUSEIPDB_API_KEY)",
    )
    parser.add_argument(
        "-m", "--max-age-days",
        type=int,
        default=90,
        help="Finestra temporale per i report AbuseIPDB in giorni (default: 90)",
    )
    parser.add_argument(
        "-o", "--output",
        default="",
        help="File CSV di output con i risultati (opzionale)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Mostra dettagli aggiuntivi",
    )
    parser.add_argument(
        "-d", "--delay",
        type=float,
        default=1.0,
        help="Secondi di attesa tra una chiamata API e l'altra (default: 1.0)",
    )
    parser.add_argument(
        "-r", "--remove",
        action="store_true",
        help="Elimina i file XML dalla cartella dopo l'analisi",
    )
    parser.add_argument(
        "-l", "--log",
        action="store_true",
        help="Accoda i record SPF-fail a 'analisi.log' nella cartella corrente",
    )

    args = parser.parse_args()

    # Validazione cartella
    folder = Path(args.folder)
    if not folder.exists() or not folder.is_dir():
        print(f"[ERRORE] La cartella '{folder}' non esiste o non è una directory.")
        sys.exit(1)

    # Validazione API key
    if not args.api_key:
        print("[ERRORE] API key mancante. Usa --api-key oppure imposta ABUSEIPDB_API_KEY.")
        sys.exit(1)

    # Decompressione archivi
    estrai_archivi(folder, verbose=args.verbose)

    # Rimozione file ._* generati da macOS (dopo rexplode)
    for mac_file in folder.glob("._*"):
        try:
            mac_file.unlink()
            if args.verbose:
                print(f"  [macOS] Rimosso: {mac_file.name}")
        except OSError as e:
            print(f"  [!] Impossibile rimuovere '{mac_file.name}': {e}")

    # Ricerca file XML (escludi comunque eventuali ._* residui)
    xml_files = sorted(f for f in folder.glob("*.xml") if not f.name.startswith("._"))
    if not xml_files:
        # Prova anche file .gz decompressi o con altro case
        xml_files = sorted(f for f in folder.glob("**/*.xml") if not f.name.startswith("._"))

    if not xml_files:
        print(f"[!] Nessun file XML trovato in '{folder}'.")
        sys.exit(0)

    print(f"\n{'='*60}")
    print(f"  DMARC SPF-Fail Analyzer + AbuseIPDB Lookup")
    print(f"{'='*60}")
    print(f"  Cartella:    {folder.resolve()}")
    print(f"  File XML:    {len(xml_files)}")
    print(f"  Max age:     {args.max_age_days} giorni")
    print(f"{'='*60}\n")

    # ── Step 1: Parsing XML ──
    all_fail_records = []
    for xml_file in xml_files:
        if args.verbose:
            print(f"[XML] Analisi: {xml_file.name}")
        records = parse_dmarc_xml(xml_file)
        if records:
            print(f"  ✓ {xml_file.name}: {len(records)} record SPF-fail trovati")
            all_fail_records.extend(records)
        elif args.verbose:
            print(f"  - {xml_file.name}: nessun SPF fail")

    # ── Rimozione file XML (prima di qualsiasi exit anticipato) ──
    if args.remove:
        removed = 0
        for xml_file in xml_files:
            try:
                xml_file.unlink()
                removed += 1
                if args.verbose:
                    print(f"  [rm] Rimosso: {xml_file.name}")
            except OSError as e:
                print(f"  [!] Impossibile rimuovere '{xml_file.name}': {e}")
        print(f"🗑️  Rimossi {removed} file XML dalla cartella '{folder}'.\n")

    if not all_fail_records:
        print("\n✅ Nessun record con SPF auth = 'fail' trovato nei file analizzati.")
        sys.exit(0)

    # Deduplica IP (ma mantieni tutti i record per il CSV)
    unique_ips = {}
    for record in all_fail_records:
        ip = record["source_ip"]
        if ip not in unique_ips:
            unique_ips[ip] = record  # Tieni il primo record come rappresentativo

    print(f"\n{'─'*60}")
    print(f"  Totale record SPF-fail:  {len(all_fail_records)}")
    print(f"  IP unici da verificare:  {len(unique_ips)}")
    print(f"{'─'*60}")

    # ── Step 2: AbuseIPDB Lookup ──
    print(f"\n[AbuseIPDB] Interrogazione in corso...\n")

    abuse_cache = {}  # ip -> risultato API
    csv_rows = []

    for i, (ip, representative_record) in enumerate(unique_ips.items(), 1):
        print(f"[{i}/{len(unique_ips)}] Verifica IP: {ip}")
        abuse_data = check_abuseipdb(ip, args.api_key, args.max_age_days)
        abuse_cache[ip] = abuse_data
        print_result(representative_record, abuse_data)

        # Pausa tra le chiamate
        if i < len(unique_ips):
            time.sleep(args.delay)

    # ── Step 3: Costruzione righe CSV (tutti i record, con dati abuse) ──
    for record in all_fail_records:
        ip = record["source_ip"]
        abuse_data = abuse_cache.get(ip) or {}
        row = {**record, **abuse_data}
        csv_rows.append(row)

    # ── Step 4: Salvataggio CSV ──
    if args.output:
        save_csv(csv_rows, args.output)

    # ── Step 5: Log ──
    if args.log:
        append_log(csv_rows)

    # ── Riepilogo finale ──
    print(f"\n{'='*60}")
    print("  RIEPILOGO FINALE")
    print(f"{'='*60}")

    high_risk = [(ip, d) for ip, d in abuse_cache.items()
                 if d and d.get("abuse_confidence_score", 0) >= 75]
    medium_risk = [(ip, d) for ip, d in abuse_cache.items()
                   if d and 25 <= d.get("abuse_confidence_score", 0) < 75]
    low_risk = [(ip, d) for ip, d in abuse_cache.items()
                if d and d.get("abuse_confidence_score", 0) < 25]
    no_data = [ip for ip, d in abuse_cache.items() if d is None]

    print(f"  🔴 Alto rischio  (score ≥ 75): {len(high_risk)} IP")
    for ip, d in high_risk:
        print(f"      {ip:20s} score={d['abuse_confidence_score']:3d}  [{d.get('country_code','??')}] {d.get('isp','')}")

    print(f"  🟠 Rischio medio (25-74):      {len(medium_risk)} IP")
    for ip, d in medium_risk:
        print(f"      {ip:20s} score={d['abuse_confidence_score']:3d}  [{d.get('country_code','??')}] {d.get('isp','')}")

    print(f"  🟢 Basso rischio (score < 25): {len(low_risk)} IP")
    print(f"  ⚪ Dati non disponibili:        {len(no_data)} IP")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
