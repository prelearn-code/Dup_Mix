from __future__ import annotations

import argparse
import ctypes
import importlib
import os
import platform
import shutil
import socket
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

PBC_CANDIDATES = ("libpbc.so", "/usr/local/lib/libpbc.so")
GMP_CANDIDATES = ("libgmp.so", "/usr/local/lib/libgmp.so")
PY_MODULES = ("web3", "solcx", "coincurve", "yaml", "dotenv", "py_ecc")


def _ok(flag: bool) -> str:
    return "OK" if flag else "MISSING"


def _load_lib(candidates: Tuple[str, ...]) -> bool:
    for candidate in candidates:
        try:
            ctypes.CDLL(candidate)
            return True
        except OSError:
            continue
    return False


def _check_modules() -> Dict[str, bool]:
    result: Dict[str, bool] = {}
    for module in PY_MODULES:
        try:
            importlib.import_module(module)
            result[module] = True
        except Exception:
            result[module] = False
    return result


def _check_rpc(host: str, port: int, timeout_sec: float = 0.6) -> Optional[bool]:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except PermissionError:
        return None
    sock.settimeout(timeout_sec)
    try:
        sock.connect((host, port))
        return True
    except Exception:
        return False
    finally:
        sock.close()


def _check_solc_versions() -> Tuple[bool, List[str]]:
    try:
        from solcx import get_installed_solc_versions

        versions = [str(v) for v in get_installed_solc_versions(solcx_binary_path=Path(".solcx"))]
        if not versions:
            versions = [str(v) for v in get_installed_solc_versions()]
        return (len(versions) > 0, versions)
    except Exception:
        return (False, [])


def _print_line(key: str, value: str) -> None:
    print(f"{key:<30} {value}")


def _python_is_310_plus() -> bool:
    return sys.version_info >= (3, 10)


def _collect() -> Dict[str, object]:
    module_status = _check_modules()
    solc_ok, solc_versions = _check_solc_versions()
    ganache_cmd = shutil.which("ganache")
    rpc_ok = _check_rpc("127.0.0.1", 7545)
    pbc_ok = _load_lib(PBC_CANDIDATES)
    gmp_ok = _load_lib(GMP_CANDIDATES)
    python_ok = _python_is_310_plus()

    full_repro = all(
        [
            python_ok,
            module_status.get("web3", False),
            module_status.get("solcx", False),
            module_status.get("py_ecc", False),
            pbc_ok,
            gmp_ok,
            ganache_cmd is not None,
            rpc_ok is True,
            solc_ok,
        ]
    )

    return {
        "os": platform.platform(),
        "python": sys.version.split()[0],
        "python_ok": python_ok,
        "venv": str(Path(sys.executable)),
        "project_root": str(PROJECT_ROOT),
        "modules": module_status,
        "libpbc_ok": pbc_ok,
        "libgmp_ok": gmp_ok,
        "ganache_cmd": ganache_cmd or "",
        "ganache_rpc_ok": rpc_ok,
        "solc_versions_installed": solc_versions,
        "full_repro": full_repro,
        "mode": "FULL_REPRO" if full_repro else "APPROX_REPRO",
    }


def _check_pbc_property() -> Tuple[bool, str]:
    try:
        from src.crypto import setup

        params = setup(sectors_per_block=8, s=b"pairing-check")
        if params.pairing_backend != "paper_pbc" or not params.use_pbc:
            return (False, "paper_pbc backend request did not activate.")
        if not params.pairing_strict:
            return (False, "paper_pbc active, but strict native pairing verification is unavailable.")
        return (True, "paper_pbc strict Type-A native C/PBC pairing_apply backend is active.")
    except Exception as exc:
        return (False, f"Error: {exc}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Check if environment matches paper reproduction requirements.")
    parser.add_argument("--json", action="store_true", help="Print raw JSON result.")
    parser.add_argument("--check-pbc-property", action="store_true", help="Run pairing sanity check hook.")
    args = parser.parse_args()

    report = _collect()

    if args.json:
        import json

        print(json.dumps(report, indent=2))
        return

    print("=== DupMix Paper Repro Environment Check ===")
    _print_line("OS", str(report["os"]))
    _print_line("Python", str(report["python"]))
    _print_line("Python>=3.10", _ok(bool(report["python_ok"])))
    _print_line("Interpreter", str(report["venv"]))
    _print_line("Project root", str(report["project_root"]))
    print("")
    print("Modules:")
    modules = report["modules"]  # type: ignore[assignment]
    for name in PY_MODULES:
        _print_line(f"  {name}", _ok(bool(modules.get(name))))  # type: ignore[union-attr]
    print("")
    _print_line("libpbc.so", _ok(bool(report["libpbc_ok"])))
    _print_line("libgmp.so", _ok(bool(report["libgmp_ok"])))
    _print_line("ganache command", report["ganache_cmd"] if report["ganache_cmd"] else "MISSING")
    rpc_value = report["ganache_rpc_ok"]
    if rpc_value is None:
        _print_line("ganache rpc 127.0.0.1:7545", "UNKNOWN (sandbox denied socket)")
    else:
        _print_line("ganache rpc 127.0.0.1:7545", _ok(bool(rpc_value)))
    solc_versions = report["solc_versions_installed"]  # type: ignore[assignment]
    if solc_versions:
        _print_line("solc versions", ", ".join(solc_versions))  # type: ignore[arg-type]
    else:
        _print_line("solc versions", "MISSING")
    if args.check_pbc_property:
        ok, msg = _check_pbc_property()
        _print_line("pairing property", _ok(ok))
        _print_line("pairing detail", msg)
    print("")
    print(f"REPRO_MODE: {report['mode']}")
    if report["full_repro"]:
        print("All strict paper conditions are available.")
    else:
        print("Strict paper conditions are not fully met. You can still run approximate reproduction.")
        print("Missing pieces are typically: PBC/GMP native libraries, Ganache RPC, or local solc.")


if __name__ == "__main__":
    main()
