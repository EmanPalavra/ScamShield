"""Compatibility launcher for the single ScamShield Cloudflare application.

Running ``python app.py`` from the repository root starts the current app in
``cloudflare-app``. The retired Flask implementation no longer lives here.
"""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys


ROOT = Path(__file__).resolve().parent
APP_DIR = ROOT / "cloudflare-app"


def find_package_command() -> list[str] | None:
    """Return the first available command capable of running package scripts."""
    pnpm = shutil.which("pnpm") or shutil.which("pnpm.cmd")
    if pnpm:
        return [pnpm]

    corepack = shutil.which("corepack") or shutil.which("corepack.cmd")
    if corepack:
        return [corepack, "pnpm"]

    npm = shutil.which("npm") or shutil.which("npm.cmd")
    if npm:
        return [npm]

    local_candidates = [
        Path.home()
        / ".cache"
        / "codex-runtimes"
        / "codex-primary-runtime"
        / "dependencies"
        / "bin"
        / "fallback"
        / "pnpm.cmd",
        Path(os.environ.get("ProgramFiles", r"C:\Program Files"))
        / "nodejs"
        / "npm.cmd",
    ]
    for candidate in local_candidates:
        if candidate.is_file():
            return [str(candidate)]

    return None


def build_child_environment() -> dict[str, str]:
    """Ensure package scripts can resolve Node even in a bundled runtime."""
    environment = os.environ.copy()
    node_candidates = [
        shutil.which("node") or shutil.which("node.exe"),
        str(
            Path.home()
            / ".cache"
            / "codex-runtimes"
            / "codex-primary-runtime"
            / "dependencies"
            / "node"
            / "bin"
            / "node.exe"
        ),
        str(
            Path(os.environ.get("ProgramFiles", r"C:\Program Files"))
            / "nodejs"
            / "node.exe"
        ),
    ]
    for node_candidate in node_candidates:
        if node_candidate and Path(node_candidate).is_file():
            node_directory = str(Path(node_candidate).resolve().parent)
            environment["PATH"] = node_directory + os.pathsep + environment.get("PATH", "")
            break
    return environment


def main() -> int:
    package_json = APP_DIR / "package.json"
    if not package_json.is_file():
        print(f"ScamShield project was not found at: {APP_DIR}", file=sys.stderr)
        return 1

    package_command = find_package_command()
    if package_command is None:
        print(
            "Node.js with pnpm or npm is required. Install Node.js 22 or newer, "
            "then run this command again.",
            file=sys.stderr,
        )
        return 1

    if not (APP_DIR / "node_modules").is_dir():
        install_command = " ".join([*package_command, "install"])
        print("ScamShield dependencies are not installed.", file=sys.stderr)
        print(f"Run: cd {APP_DIR} && {install_command}", file=sys.stderr)
        return 1

    runner = [*package_command, "run", "dev"]
    if sys.argv[1:]:
        is_pnpm = any("pnpm" in Path(part).name.lower() for part in package_command)
        runner.extend([*([] if is_pnpm else ["--"]), *sys.argv[1:]])
    print("Starting the current ScamShield application from cloudflare-app...")
    print("The local URL will appear below. Press Ctrl+C to stop the server.")

    try:
        completed = subprocess.run(
            runner,
            cwd=APP_DIR,
            check=False,
            env=build_child_environment(),
            shell=False,
        )
        return completed.returncode
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
