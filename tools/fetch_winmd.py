#!/usr/bin/env python3
"""Fetch real Windows API metadata (WinMD) without a Windows SDK.

The metadata is restored with the installed `dotnet` from NuGet into a
gitignored cache, then the `.winmd` payloads are copied into a deterministic
layout and recorded in `manifest.json` (path + SHA-256 + size).  Re-running is
a no-op when the manifest matches, so `casa1-oracle inventory --winmd
.cache/winmd` always sees the same bytes.

Pinned packages (documented here and in the generated manifest):

  * Microsoft.Windows.SDK.Win32Metadata  71.0.37-preview
      supplies Windows.Win32.winmd (functions, module refs, interfaces)
  * Microsoft.Windows.SDK.Contracts      10.0.28000.2957
      supplies the Windows.* WinRT contract winmd files

Usage:
    python3 tools/fetch_winmd.py [--cache .cache/winmd] [--force]

The script never vendors binaries into git; `.cache/` is ignored.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import shutil
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

PACKAGES = {
    "Microsoft.Windows.SDK.Win32Metadata": "71.0.37-preview",
    "Microsoft.Windows.SDK.Contracts": "10.0.28000.2957",
}
MANIFEST_SCHEMA = 1
MANIFEST_NAME = "manifest.json"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def dotnet_version() -> str:
    try:
        result = subprocess.run(
            ["dotnet", "--version"], capture_output=True, text=True, check=True
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise SystemExit(f"dotnet is required to fetch WinMD metadata: {error}")
    return result.stdout.strip()


def manifest_is_current(cache: pathlib.Path) -> bool:
    path = cache / MANIFEST_NAME
    if not path.is_file():
        return False
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    if manifest.get("schema_version") != MANIFEST_SCHEMA:
        return False
    packages = manifest.get("packages") or []
    found = {entry.get("id"): entry.get("version") for entry in packages}
    if found != PACKAGES:
        return False
    for package in packages:
        for item in package.get("files") or []:
            target = cache / item["path"]
            if not target.is_file():
                return False
            if target.stat().st_size != item["size_bytes"]:
                return False
            if sha256_file(target) != item["sha256"]:
                return False
    return True


def write_project(project: pathlib.Path, packages: pathlib.Path) -> pathlib.Path:
    project.mkdir(parents=True, exist_ok=True)
    references = "\n".join(
        f'    <PackageReference Include="{package_id}" Version="{version}" />'
        for package_id, version in sorted(PACKAGES.items())
    )
    (project / "fetch.csproj").write_text(
        "<Project Sdk=\"Microsoft.NET.Sdk\">\n"
        "  <PropertyGroup>\n"
        "    <TargetFramework>net8.0</TargetFramework>\n"
        "    <EnableDefaultCompileItems>false</EnableDefaultCompileItems>\n"
        "  </PropertyGroup>\n"
        "  <ItemGroup>\n"
        f"{references}\n"
        "  </ItemGroup>\n"
        "</Project>\n",
        encoding="utf-8",
    )
    config = project / "nuget.config"
    config.write_text(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
        "<configuration>\n"
        "  <packageSources>\n"
        "    <clear />\n"
        "    <add key=\"nuget.org\" value=\"https://api.nuget.org/v3/index.json\" />\n"
        "  </packageSources>\n"
        "</configuration>\n",
        encoding="utf-8",
    )
    print(f":: restoring {', '.join(f'{k} {v}' for k, v in sorted(PACKAGES.items()))}")
    subprocess.run(
        [
            "dotnet",
            "restore",
            str(project / "fetch.csproj"),
            "--packages",
            str(packages),
            "--configfile",
            str(config),
            "--nologo",
            "--verbosity",
            "minimal",
        ],
        check=True,
    )
    return packages


def collect(cache: pathlib.Path, packages: pathlib.Path) -> dict:
    entries = []
    for package_id in sorted(PACKAGES):
        version = PACKAGES[package_id]
        root = packages / package_id.lower() / version
        if not root.is_dir():
            raise SystemExit(f"restored package missing: {root}")
        winmd_files = sorted(root.rglob("*.winmd"))
        if not winmd_files:
            raise SystemExit(f"package {package_id} {version} contains no .winmd files")
        files = []
        for source in winmd_files:
            relative = source.relative_to(root)
            target = cache / package_id.lower() / version / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
            data = target.read_bytes()
            files.append(
                {
                    "path": target.relative_to(cache).as_posix(),
                    "sha256": sha256_bytes(data),
                    "size_bytes": len(data),
                }
            )
        entries.append(
            {
                "id": package_id,
                "version": version,
                "files": sorted(files, key=lambda item: item["path"]),
            }
        )
    return {
        "schema_version": MANIFEST_SCHEMA,
        "generator": "tools/fetch_winmd.py",
        "dotnet": dotnet_version(),
        "packages": entries,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--cache",
        type=pathlib.Path,
        default=ROOT / ".cache" / "winmd",
        help="cache directory (default: <repo>/.cache/winmd)",
    )
    parser.add_argument(
        "--force", action="store_true", help="re-restore even when the cache matches"
    )
    args = parser.parse_args()

    cache = args.cache.resolve()
    if not args.force and manifest_is_current(cache):
        print(f":: WinMD cache up to date: {cache}")
        for package_id, version in sorted(PACKAGES.items()):
            print(f"::   {package_id} {version}")
        return 0

    cache.mkdir(parents=True, exist_ok=True)
    work = cache / ".fetch"
    packages = work / "packages"
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)
    try:
        write_project(work, packages)
        manifest = collect(cache, packages)
    finally:
        shutil.rmtree(work, ignore_errors=True)

    manifest_path = cache / MANIFEST_NAME
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    winmd_count = sum(len(package["files"]) for package in manifest["packages"])
    print(f":: wrote {winmd_count} winmd file(s)")
    print(f":: manifest: {manifest_path}")
    print(f":: inventory with: casa1-oracle inventory --winmd {cache} --out winmd.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
