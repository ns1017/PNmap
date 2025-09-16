#!/usr/bin/env python3
# portable_scanner.py
# USB-optimized Nmap scanner (PyInstaller-friendly)
#
# - Designed to run from a PyInstaller --onefile EXE launched from a USB stick
# - Looks for bundled nmap (nmap.exe) in the extracted bundle dir (_MEIPASS) or next to the EXE
# - Default: TCP connect (-sT) and common ports 1-1024 for fast scans without raw sockets or Npcap
# - Lightweight extractive summarizer used by default (no heavy ML dependencies)
#
# Packaging notes:
# - Include nmap.exe and required DLLs in --add-binary (or place them in nmap_bin/) when building with PyInstaller
# - Use --onefile to ensure the runtime extracts binaries to a temp folder (safer than running directly off the USB)
#
# Author: ns1017 on Github, Data Analyst GPT (for help with comments and structure) 
# Date: 2025-09-16

from __future__ import annotations
import argparse
import sys
import os
import time
import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

# --------------------
# USB / PyInstaller runtime helpers
# --------------------
def get_runtime_bundle_dir() -> str:
    """
    Return directory where bundled resources will be extracted at runtime (PyInstaller _MEIPASS)
    or the directory where the script/exe lives. This must be called before importing modules
    that rely on bundled binaries (like python-nmap which will call the system 'nmap' binary).
    """
    if getattr(sys, "frozen", False):
        # PyInstaller onefile: binaries/data are extracted to _MEIPASS
        meipass = getattr(sys, "_MEIPASS", None)
        if meipass and os.path.isdir(meipass):
            return meipass
    # fallback: directory containing the running script or exe
    return os.path.dirname(os.path.abspath(sys.argv[0] if getattr(sys, "frozen", False) else __file__))

def find_bundled_nmap(bundle_dir: str) -> Optional[str]:
    """
    Search for nmap executable in bundle_dir and common subfolder(s).
    Returns full path to nmap executable if found, otherwise None.
    """
    candidates = []
    is_windows = os.name == "nt"
    exe_names = ["nmap.exe"] if is_windows else ["nmap"]
    # check bundle root and common subfolder
    possible_dirs = [bundle_dir, os.path.join(bundle_dir, "nmap_bin"), os.path.join(bundle_dir, "nmap"), os.path.join(bundle_dir, "bin")]
    for d in possible_dirs:
        for name in exe_names:
            path = os.path.join(d, name)
            candidates.append(path)
    # also check PATH (in case system nmap exists)
    for name in exe_names:
        which = shutil_which(name)
        if which:
            candidates.append(which)
    for c in candidates:
        try:
            if c and os.path.isfile(c) and os.access(c, os.X_OK):
                return os.path.abspath(c)
        except Exception:
            continue
    return None

def shutil_which(cmd: str) -> Optional[str]:
    """
    Lightweight replacement wrapper for shutil.which to avoid import ordering issues in some frozen runtimes.
    """
    try:
        import shutil
        return shutil.which(cmd)
    except Exception:
        return None

def ensure_nmap_on_path(nmap_path: Optional[str], bundle_dir: str):
    """
    If a bundled nmap was found, prepend its directory to PATH so python-nmap and subprocess can find it.
    If nmap_path is None, does nothing; caller should handle error/warning.
    """
    if not nmap_path:
        return
    nmap_dir = os.path.dirname(nmap_path)
    if nmap_dir:
        os.environ["PATH"] = nmap_dir + os.pathsep + os.environ.get("PATH", "")

# --------------------
# Logging (file logger always written to working dir; console logging optional)
# --------------------
LOGFILE = "scanner_log.txt"
logger = logging.getLogger("usb-portable-nmap")
logger.setLevel(logging.INFO)
fh = logging.FileHandler(LOGFILE, encoding="utf-8")
fh.setLevel(logging.INFO)
fh.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
logger.addHandler(fh)

# console handler (added only when verbose)
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setFormatter(logging.Formatter("%(message)s"))

# --------------------
# Lightweight extractive summarizer
# --------------------
def simple_extractive_summary(text: str, max_chars: int = 240) -> str:
    if not text:
        return ""
    text = text.strip()
    if len(text) <= max_chars:
        return text
    # cut at last sentence boundary within max_chars
    end = text.rfind(".", 0, max_chars)
    if end == -1:
        end = text.rfind("\n", 0, max_chars)
    if end == -1:
        end = max_chars
    summary = text[:end].strip()
    if len(summary) < 20:
        summary = text[:max_chars].strip()
    if not summary.endswith("."):
        summary = summary.rstrip() + " ..."
    return summary

# --------------------
# Delay importing nmap until we've adjusted PATH to include bundled nmap
# --------------------
nmap = None
def import_nmap_lazily():
    global nmap
    if nmap is not None:
        return
    try:
        import nmap as _nmap  # python-nmap
        nmap = _nmap
    except Exception as e:
        logger.error(f"Unable to import python-nmap: {e}")
        nmap = None

# --------------------
# Scanning and parsing
# --------------------
DEFAULT_PORTS = "1-1024"

def run_nmap_scan(target: str, ports: str = DEFAULT_PORTS, use_syn: bool = False, extra_args: Optional[str] = None) -> Dict[str, Any]:
    """
    Run nmap scan using python-nmap. The function expects that ensure_nmap_on_path() was called
    earlier so that the correct nmap binary is discoverable.
    """
    import_nmap_lazily()
    if nmap is None:
        raise RuntimeError("python-nmap is not available. Ensure python-nmap is installed or that packaging included it.")

    nm = nmap.PortScanner()
    args = []
    if use_syn:
        args.append("-sS")
    else:
        args.append("-sT")
    args.append("-sV")
    args.append("-Pn")
    if extra_args:
        args.extend(extra_args.split())

    argstr = " ".join(args)
    logger.info(f"Running nmap: target={target} ports={ports} args={argstr}")
    try:
        scan_result = nm.scan(hosts=target, ports=ports, arguments=argstr)
        return scan_result
    except Exception as e:
        logger.exception("Nmap scan failed")
        raise RuntimeError(f"Nmap scan failed: {e}")

def parse_nmap_output(scan_result: Dict[str, Any], use_hf_callable=None) -> List[Dict[str, Any]]:
    hosts_out: List[Dict[str, Any]] = []
    # defensive handling of common python-nmap structures
    scan_scan = scan_result.get("scan") if isinstance(scan_result, dict) else {}
    # If scan_scan empty, attempt to use scan_result directly
    if not scan_scan:
        scan_scan = scan_result if isinstance(scan_result, dict) else {}
    for host, hdict in scan_scan.items():
        if host in ("nmap", "scaninfo", "stats"):
            continue
        if not isinstance(hdict, dict):
            hdict = {}
        hostname = ""
        try:
            hostnames = hdict.get("hostnames", [])
            if isinstance(hostnames, list) and hostnames:
                # python-nmap stores hostnames as list of dicts
                hostname = hostnames[0].get("name", "") if isinstance(hostnames[0], dict) else str(hostnames[0])
        except Exception:
            hostname = ""

        host_entry = {
            "ip": host,
            "hostname": hostname,
            "open_ports": [],
            "hostscripts": [],
            "scan_metadata": {"scanned_at": datetime.utcnow().isoformat() + "Z"}
        }

        for proto in ("tcp", "udp", "sctp"):
            proto_dict = hdict.get(proto) or {}
            if not isinstance(proto_dict, dict):
                continue
            for port_key, port_info in proto_dict.items():
                try:
                    port_num = int(port_key)
                except Exception:
                    try:
                        port_num = int(str(port_key).split("/")[0])
                    except Exception:
                        continue
                if not isinstance(port_info, dict):
                    continue
                state = port_info.get("state", "")
                service = port_info.get("name", "") or port_info.get("service", "")
                product = port_info.get("product", "")
                version = port_info.get("version", "")
                scripts_list = []
                pscript = port_info.get("script") or port_info.get("scripts") or {}
                if isinstance(pscript, dict):
                    for sid, out in pscript.items():
                        out_text = out or ""
                        summary = simple_extractive_summary(out_text)
                        # optional HF summarizer support (if caller passed callable)
                        if use_hf_callable and isinstance(out_text, str) and len(out_text) > 80:
                            try:
                                res = use_hf_callable(out_text, max_length=120, min_length=30)
                                if isinstance(res, list) and res and "summary_text" in res[0]:
                                    summary = res[0]["summary_text"]
                            except Exception as e:
                                logger.debug(f"HF summarizer error (port script): {e}")
                        scripts_list.append({"id": sid, "output": out_text, "summary": summary})
                elif isinstance(pscript, list):
                    for s in pscript:
                        sid = s.get("id")
                        out_text = s.get("output") or ""
                        summary = simple_extractive_summary(out_text)
                        scripts_list.append({"id": sid, "output": out_text, "summary": summary})

                host_entry["open_ports"].append({
                    "port": port_num,
                    "protocol": proto,
                    "state": state,
                    "service": service,
                    "product": product,
                    "version": version,
                    "scripts": scripts_list
                })

        hostscripts = hdict.get("hostscript") or hdict.get("host_scripts") or []
        if isinstance(hostscripts, list):
            for hs in hostscripts:
                out_text = hs.get("output") or ""
                summary = simple_extractive_summary(out_text)
                host_entry["hostscripts"].append({"id": hs.get("id"), "output": out_text, "summary": summary})

        host_entry["open_ports"] = sorted(host_entry["open_ports"], key=lambda x: (x["protocol"], x["port"]))
        hosts_out.append(host_entry)

    return hosts_out

# --------------------
# Reporting
# --------------------
def generate_text_report(hosts: List[Dict[str, Any]]) -> str:
    lines = []
    lines.append("Portable Nmap Scanner Report")
    lines.append(f"Generated: {datetime.utcnow().isoformat()}Z")
    lines.append("=" * 60)
    for h in hosts:
        lines.append(f"Host: {h.get('ip')} ({h.get('hostname','')})")
        lines.append("-" * 40)
        if not h.get("open_ports"):
            lines.append("  No open ports detected.")
        else:
            for p in h.get("open_ports", []):
                serv = p.get("service") or ""
                prod = p.get("product") or ""
                ver = p.get("version") or ""
                lines.append(f"  {p.get('protocol')}/{p.get('port')}: {p.get('state')} - {serv} {prod} {ver}".strip())
                for s in p.get("scripts", []):
                    lines.append(f"    Script: {s.get('id')}")
                    if s.get("summary"):
                        lines.append(f"      {s.get('summary')}")
    lines.append("")
    return "\n".join(lines)

def write_report_files(hosts: List[Dict[str, Any]], out_dir: str = ".", prefix: str = "scan_report"):
    ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    text_name = os.path.join(out_dir, f"{prefix}_{ts}.txt")
    json_name = os.path.join(out_dir, f"{prefix}_{ts}.json")
    try:
        os.makedirs(out_dir, exist_ok=True)
    except Exception as e:
        logger.warning(f"Could not create out_dir {out_dir}: {e}")
    text = generate_text_report(hosts)
    try:
        with open(text_name, "w", encoding="utf-8") as f:
            f.write(text)
        print(f"Wrote text report: {text_name}")
        logger.info(f"Wrote text report: {text_name}")
    except Exception as e:
        logger.error(f"Failed to write text report: {e}")
        print(f"Failed to write text report: {e}")
    try:
        with open(json_name, "w", encoding="utf-8") as f:
            json.dump({"generated_at": datetime.utcnow().isoformat() + "Z", "hosts": hosts}, f, indent=2)
        print(f"Wrote JSON report: {json_name}")
        logger.info(f"Wrote JSON report: {json_name}")
    except Exception as e:
        logger.error(f"Failed to write JSON report: {e}")
        print(f"Failed to write JSON report: {e}")

# --------------------
# CLI
# --------------------
def build_parser():
    p = argparse.ArgumentParser(description="USB-optimized portable Nmap scanner")
    p.add_argument("target", help="Target CIDR or IP (e.g., 192.168.1.0/24 or 10.0.0.5)")
    p.add_argument("-p", "--ports", default=DEFAULT_PORTS, help="Port range (default: 1-1024)")
    p.add_argument("--synth", action="store_true", help="Use SYN scan (-sS). Requires admin/Npcap on Windows.")
    p.add_argument("--nmap-path", default=None, help="Path to nmap executable to use (overrides bundled search).")
    p.add_argument("--extra-args", default=None, help="Extra args to pass to nmap")
    p.add_argument("--out-dir", default=".", help="Output directory for reports (default: current dir)")
    p.add_argument("--yes", action="store_true", help="Skip legal confirmation prompt")
    p.add_argument("--verbose", action="store_true", help="Enable console logging")
    # Keep --use-ml option for advanced users who build a large bundle
    p.add_argument("--use-ml", action="store_true", help="(optional) Enable HF summarizer (only if packaged with models & transformers)")
    p.add_argument("--model", default="sshleifer/distilbart-cnn-12-6", help="HF model name if --use-ml is used")
    return p

def confirm_legal(target: str, yes: bool = False) -> bool:
    if yes:
        return True
    disclaimer = f"""
You are about to scan target: {target}

IMPORTANT: Only scan systems you own or have explicit authorization to test.
Unauthorized scanning may be illegal and unethical.

Do you confirm you have authorization to scan the target? (y/N):
"""
    ans = input(disclaimer).strip().lower()
    return ans in ("y", "yes")

def main(argv: Optional[List[str]] = None) -> int:
    # Determine bundle dir and attempt to locate nmap before importing python-nmap
    bundle_dir = get_runtime_bundle_dir()
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.verbose:
        logger.setLevel(logging.DEBUG)
        fh.setLevel(logging.DEBUG)
        console_handler.setLevel(logging.DEBUG)
        logger.addHandler(console_handler)
        print("Verbose logging enabled.")

    # try to find bundled nmap (unless user supplied --nmap-path)
    nmap_exe_path = None
    if args.nmap_path:
        nmap_exe_path = os.path.abspath(args.nmap_path)
        if not (os.path.isfile(nmap_exe_path) and os.access(nmap_exe_path, os.X_OK)):
            print(f"Provided nmap path not usable: {nmap_exe_path}")
            logger.warning(f"Provided nmap path not usable: {nmap_exe_path}")
            nmap_exe_path = None

    # search bundled locations only if user did not provide explicit nmap path
    if nmap_exe_path is None:
        # import shutil.which lazily optionally
        nmap_exe_path = find_bundled_nmap(bundle_dir)

    if nmap_exe_path:
        ensure_nmap_on_path(nmap_exe_path, bundle_dir)
        logger.info(f"Using nmap binary at: {nmap_exe_path}")
    else:
        # not found: warn user but continue — python-nmap may find system nmap in PATH
        logger.warning("nmap binary not found in bundle or PATH. Scans will fail unless nmap is installed on the host.")
        print("Warning: nmap executable not found in bundle or PATH. Please include nmap.exe in the bundle or install nmap on the host.")

    if not confirm_legal(args.target, yes=args.yes):
        print("Confirmation not provided. Exiting.")
        return 2

    # import python-nmap now that PATH is adjusted
    import_nmap_lazily()
    if nmap is None:
        print("python-nmap library not available. Ensure your build included python-nmap or install it in the environment.")
        logger.error("python-nmap not available.")
        return 4

    # enforce safe defaults
    use_syn = bool(args.synth)
    if use_syn:
        print("SYN scan requested. This requires Npcap/winpcap and often admin privileges. If the scan fails, rerun with TCP connect (-sT).")
        logger.info("User requested SYN scan (may require admin/Npcap).")

    # run scan
    try:
        scan_result = run_nmap_scan(target=args.target, ports=args.ports, use_syn=use_syn, extra_args=args.extra_args)
    except Exception as e:
        print(f"Scan failed: {e}")
        logger.exception("Scan failed")
        return 3

    parsed = parse_nmap_output(scan_result, use_hf_callable=None)
    print("=" * 60)
    print(f"Scan target: {args.target}")
    print(f"Hosts discovered: {len(parsed)}")
    for h in parsed:
        ports = ", ".join([f"{p['protocol']}/{p['port']}" for p in h.get("open_ports", [])])
        print(f" - {h.get('ip')} ({h.get('hostname','')}): {ports or 'no open ports'}")

    write_report_files(parsed, out_dir=args.out_dir)

    print("Scan complete.")
    return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("Interrupted by user.")
        sys.exit(1)
    except Exception as e:
        logger.exception("Unhandled error")
        print(f"Unhandled error: {e}")
        sys.exit(1)
