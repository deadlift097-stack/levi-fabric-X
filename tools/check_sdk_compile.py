#!/usr/bin/env python3
"""Compile the generated Hooks.cpp / Resolve.cpp against the REAL preloader-android SDK headers (tag pinned by the template).

Host syntax check only (-fsyntax-only, C++20, -Wall -Wextra): jni.h and android/log.h are stubbed, fmt is header-only.
It forces a hook for every statically verified function so every C++ signature in the DB is exercised.
usage: python tools/check_sdk_compile.py [--cache DIR]      exit 0 = compiles, 2 = SDK could not be fetched
"""
import argparse, pathlib, shutil, subprocess, sys, tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
PRELOADER_TAG, FMT_TAG = "0.2.2", "11.2.0"   # keep in sync with levipack_forge/template/CMakeLists.txt


def fetch(cache):
    cache.mkdir(parents=True, exist_ok=True)
    for name, url, tag in (("preloader", "https://github.com/LiteLDev/preloader-android", PRELOADER_TAG),
                           ("fmt", "https://github.com/fmtlib/fmt", FMT_TAG)):
        d = cache / f"{name}-{tag}"
        if not d.exists():
            r = subprocess.run(["git", "clone", "-q", "--depth", "1", "--branch", tag, url, str(d)], capture_output=True, text=True)
            if r.returncode:
                shutil.rmtree(d, ignore_errors=True)
                print("cannot fetch", url, r.stderr.strip()[-200:], file=sys.stderr)
                return None
    return cache / f"preloader-{PRELOADER_TAG}/include", cache / f"fmt-{FMT_TAG}/include"


def main(argv=None):
    ap = argparse.ArgumentParser(); ap.add_argument("--cache", default=str(pathlib.Path(tempfile.gettempdir()) / "levipack-sdk"))
    a = ap.parse_args(argv)
    got = fetch(pathlib.Path(a.cache))
    if not got:
        return 2
    pre, fmt = got
    from levipack_forge import hooks
    from levipack_forge.symbols import SymbolIndex
    sym = SymbolIndex.load(None)
    forced = {n: {} for n in sym.db.functions if sym.db.usable(n)}
    # also one body override using K/self/modLog, as the live test does
    forced["Item::getAttackDamage"] = {"cpp": 'const int r = orig(self) + 3; modLog().info("x {} {}", K, self); return r;'}
    with tempfile.TemporaryDirectory() as tmp:
        tmp = pathlib.Path(tmp); (tmp / "mod").mkdir()
        hh, hc = hooks.render("demo", [], [], sym, forced)
        rh, rc = hooks.render_resolve("demo")
        for n, t in (("Hooks.h", hh), ("Hooks.cpp", hc), ("Resolve.h", rh), ("Resolve.cpp", rc)):
            (tmp / "mod" / n).write_text(t)
        (tmp / "jni.h").write_text("#pragma once\nstruct _JavaVM; typedef _JavaVM JavaVM; struct _JNIEnv; typedef _JNIEnv JNIEnv;\n")
        (tmp / "android").mkdir()
        (tmp / "android/log.h").write_text("#pragma once\ntypedef enum { ANDROID_LOG_DEBUG=3, ANDROID_LOG_INFO, ANDROID_LOG_WARN, ANDROID_LOG_ERROR } android_LogPriority;\n"
                                           "inline int __android_log_write(int,const char*,const char*){return 0;}\n"
                                           "inline int __android_log_print(int,const char*,const char*,...){return 0;}\n")
        for src in ("Resolve.cpp", "Hooks.cpp"):
            r = subprocess.run(["g++", "-std=c++20", "-Wall", "-Wextra", "-fsyntax-only", "-DFMT_HEADER_ONLY", f"-I{tmp}",
                                f"-I{pre}", f"-I{fmt}", str(tmp / "mod" / src)], capture_output=True, text=True)
            if r.returncode:
                print(r.stderr, file=sys.stderr); return 1
    print(f"generated hooks compile against preloader-android {PRELOADER_TAG} + fmt {FMT_TAG} ({len(forced)} targets)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
