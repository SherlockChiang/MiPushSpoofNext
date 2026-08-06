#!/usr/bin/env python3
import argparse
import os
import pathlib
import tempfile
import zipfile


ROOT_FILES = {
    ".gitattributes", ".gitignore", "CHANGELOG.md", "LICENSE", "NOTICE.md", "README.md",
}
SOURCE_DIRECTORIES = {".github", "docs", "module", "native/jni", "scripts", "tests"}


def collect_files(root):
    paths = []
    for name in sorted(ROOT_FILES):
        path = root / name
        if not path.is_file():
            raise SystemExit(f"missing source file: {path}")
        paths.append(path)
    for name in sorted(SOURCE_DIRECTORIES):
        directory = root / name
        if not directory.is_dir():
            raise SystemExit(f"missing source directory: {directory}")
        for path in sorted(directory.rglob("*")):
            if path.is_symlink():
                raise SystemExit(f"source symlink is forbidden: {path}")
            if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc":
                paths.append(path)
    return paths


def package_source(root, output):
    version_lines = [
        line.split("=", 1)[1]
        for line in (root / "module/module.prop").read_text(encoding="utf-8").splitlines()
        if line.startswith("version=")
    ]
    if len(version_lines) != 1 or not version_lines[0]:
        raise SystemExit("module.prop must contain exactly one version")
    prefix = f"MiPushSpoofNext-{version_lines[0]}"
    files = collect_files(root)
    expected = {f"{prefix}/{path.relative_to(root).as_posix()}" for path in files}

    output.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{output.name}.", dir=output.parent)
    os.close(fd)
    temporary = pathlib.Path(temporary_name)
    try:
        with zipfile.ZipFile(temporary, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
            for path in files:
                name = f"{prefix}/{path.relative_to(root).as_posix()}"
                info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                info.create_system = 3
                executable = path.suffix == ".sh" or path.name in {"mipushctl", "update-binary"}
                info.external_attr = ((0o100755 if executable else 0o100644) << 16)
                archive.writestr(info, path.read_bytes(), compresslevel=9)

        with zipfile.ZipFile(temporary) as archive:
            names = archive.namelist()
            if len(names) != len(set(names)) or set(names) != expected:
                raise SystemExit("source ZIP manifest verification failed")
            corrupt = archive.testzip()
            if corrupt is not None:
                raise SystemExit(f"source ZIP CRC check failed: {corrupt}")
        os.replace(temporary, output)
    finally:
        temporary.unlink(missing_ok=True)
    print(f"packaged {len(files)} source files: {output}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=pathlib.Path)
    parser.add_argument("output", type=pathlib.Path)
    args = parser.parse_args()
    package_source(args.root.resolve(), args.output.resolve())


if __name__ == "__main__":
    main()
