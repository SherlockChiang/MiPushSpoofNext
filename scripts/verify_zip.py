#!/usr/bin/env python3
import argparse
import hashlib
import os
import pathlib
import re
import stat
import struct
import subprocess
import sys
import tempfile
import zipfile


ROOT = pathlib.Path(__file__).resolve().parents[1]
EXPECTED_ELF = {
    "zygisk/armeabi-v7a.so": (1, 40, "armeabi-v7a/libmipushspoofnext.so"),
    "zygisk/arm64-v8a.so": (2, 183, "arm64-v8a/libmipushspoofnext.so"),
    "zygisk/x86.so": (1, 3, "x86/libmipushspoofnext.so"),
    "zygisk/x86_64.so": (2, 62, "x86_64/libmipushspoofnext.so"),
}
EXPECTED_EXPORTS = {"zygisk_module_entry", "zygisk_companion_entry"}
REQUIRED_NOTICES = {"LICENSE", "NOTICE.md", "SOURCE.md"}


def fail(message):
    raise SystemExit(message)


def canonical_entry(name):
    if "\\" in name or name.startswith("/") or name.startswith("./"):
        fail(f"unsafe ZIP path: {name!r}")
    is_directory = name.endswith("/")
    core = name[:-1] if is_directory else name
    parts = core.split("/")
    if not core or any(part in {"", ".", ".."} for part in parts):
        fail(f"non-canonical ZIP path: {name!r}")
    if ":" in parts[0]:
        fail(f"drive-qualified ZIP path: {name!r}")
    canonical = "/".join(parts) + ("/" if is_directory else "")
    if canonical != name:
        fail(f"non-canonical ZIP path: {name!r}")
    return core, is_directory


def module_files(module_dir):
    files = {}
    for path in sorted(module_dir.rglob("*")):
        if path.is_symlink():
            fail(f"module source contains symlink: {path}")
        if path.is_file():
            name = path.relative_to(module_dir).as_posix()
            files[name] = path.read_bytes()
    missing = REQUIRED_NOTICES - files.keys()
    if missing:
        fail(f"module source is missing notices: {sorted(missing)}")
    return files


def load_alignments(data, elf_class):
    if len(data) < 64 or data[:4] != b"\x7fELF" or data[5] != 1:
        fail("ELF is truncated or is not little-endian")
    if elf_class == 1:
        phoff = struct.unpack_from("<I", data, 28)[0]
        phentsize, phnum = struct.unpack_from("<HH", data, 42)
        minimum_size, align_offset, align_format = 32, 28, "<I"
    else:
        phoff = struct.unpack_from("<Q", data, 32)[0]
        phentsize, phnum = struct.unpack_from("<HH", data, 54)
        minimum_size, align_offset, align_format = 56, 48, "<Q"
    if phentsize < minimum_size or phoff + phentsize * phnum > len(data):
        fail("ELF program header table is invalid")
    alignments = []
    for index in range(phnum):
        entry = phoff + index * phentsize
        program_type = struct.unpack_from("<I", data, entry)[0]
        if program_type == 1:  # PT_LOAD
            alignments.append(struct.unpack_from(align_format, data, entry + align_offset)[0])
    return alignments


def tool_path(llvm_bin, basename):
    suffix = ".exe" if os.name == "nt" else ""
    path = llvm_bin / f"{basename}{suffix}"
    if not path.is_file():
        fail(f"missing LLVM tool: {path}")
    return path


def verify_dynamic_interface(llvm_bin, name, data):
    nm = tool_path(llvm_bin, "llvm-nm")
    readelf = tool_path(llvm_bin, "llvm-readelf")
    with tempfile.TemporaryDirectory(prefix="mipush-verify-") as directory:
        path = pathlib.Path(directory) / pathlib.PurePosixPath(name).name
        path.write_bytes(data)
        nm_result = subprocess.run(
            [str(nm), "-D", "--defined-only", "--extern-only", str(path)],
            check=True, capture_output=True, text=True,
        )
        exports = set()
        for line in nm_result.stdout.splitlines():
            match = re.search(r"\s[ABDGRSTVW]\s+(\S+)$", line)
            if match:
                exports.add(match.group(1).split("@", 1)[0])
        if exports != EXPECTED_EXPORTS:
            fail(f"{name}: unexpected dynamic exports: {sorted(exports)}")

        needed_result = subprocess.run(
            [str(readelf), "--needed-libs", str(path)],
            check=True, capture_output=True, text=True,
        )
        needed = {
            line.strip() for line in needed_result.stdout.splitlines()
            if line.strip().endswith(".so")
        }
        forbidden = {lib for lib in needed if "c++" in lib or "stdc++" in lib}
        if forbidden:
            fail(f"{name}: forbidden C++ runtime dependency: {sorted(forbidden)}")
        if "libc.so" not in needed or "liblog.so" not in needed:
            fail(f"{name}: unexpected native dependencies: {sorted(needed)}")


def verify_zip(path, module_dir, native_libs_dir, llvm_bin):
    expected_module = module_files(module_dir)
    expected_names = set(expected_module) | set(EXPECTED_ELF)

    with zipfile.ZipFile(path) as archive:
        infos = archive.infolist()
        raw_names = [info.filename for info in infos]
        if len(raw_names) != len(set(raw_names)):
            duplicates = sorted({name for name in raw_names if raw_names.count(name) > 1})
            fail(f"duplicate ZIP entries: {duplicates}")

        file_infos = {}
        directories = set()
        for info in infos:
            core, is_directory = canonical_entry(info.filename)
            mode = (info.external_attr >> 16) & 0xFFFF
            if mode and stat.S_IFMT(mode) == stat.S_IFLNK:
                fail(f"ZIP symlink is forbidden: {info.filename}")
            if info.flag_bits & 0x1:
                fail(f"encrypted ZIP entry is forbidden: {info.filename}")
            if is_directory:
                directories.add(core)
            else:
                file_infos[core] = info

        actual_names = set(file_infos)
        if actual_names != expected_names:
            missing = sorted(expected_names - actual_names)
            extra = sorted(actual_names - expected_names)
            fail(f"ZIP file manifest mismatch; missing={missing}, extra={extra}")
        valid_directories = {
            "/".join(name.split("/")[:index])
            for name in expected_names
            for index in range(1, len(name.split("/")))
        }
        if not directories <= valid_directories:
            fail(f"unexpected ZIP directories: {sorted(directories - valid_directories)}")

        corrupt = archive.testzip()
        if corrupt is not None:
            fail(f"ZIP CRC check failed: {corrupt}")

        for name, source_data in expected_module.items():
            archived = archive.read(file_infos[name])
            if archived != source_data:
                fail(f"{name}: ZIP content differs from module source")

        for name, (elf_class, machine, source_name) in EXPECTED_ELF.items():
            data = archive.read(file_infos[name])
            if native_libs_dir is not None:
                source_path = native_libs_dir / pathlib.PurePosixPath(source_name)
                if not source_path.is_file():
                    fail(f"missing generated native library: {source_path}")
                if data != source_path.read_bytes():
                    fail(f"{name}: ZIP content differs from generated native library")
            if data[:4] != b"\x7fELF" or data[4] != elf_class:
                fail(f"{name}: wrong ELF class")
            actual_machine = int.from_bytes(data[18:20], "little")
            if actual_machine != machine:
                fail(f"{name}: expected machine {machine}, got {actual_machine}")
            alignments = load_alignments(data, elf_class)
            if not alignments or min(alignments) < 0x4000:
                fail(f"{name}: LOAD alignment is not 16 KiB: {alignments}")
            if llvm_bin is not None:
                verify_dynamic_interface(llvm_bin, name, data)
            print(
                f"{name}: {len(data)} bytes align={min(alignments):#x} "
                f"sha256={hashlib.sha256(data).hexdigest()}"
            )
    print(f"verified exact source manifest and ELF interface: {path}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("zip_path", type=pathlib.Path)
    parser.add_argument("--module-dir", type=pathlib.Path, default=ROOT / "module")
    parser.add_argument("--native-libs-dir", type=pathlib.Path)
    parser.add_argument("--llvm-bin", type=pathlib.Path)
    args = parser.parse_args()
    verify_zip(
        args.zip_path.resolve(), args.module_dir.resolve(),
        args.native_libs_dir.resolve() if args.native_libs_dir else None,
        args.llvm_bin.resolve() if args.llvm_bin else None,
    )


if __name__ == "__main__":
    main()
