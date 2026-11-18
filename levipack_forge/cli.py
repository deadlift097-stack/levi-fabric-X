from __future__ import annotations
import argparse, json, sys
from . import __version__


def main(argv=None):
    ap = argparse.ArgumentParser(prog="levipack-forge", description="Fabric mod (.jar) -> LeviLauncher Android .levipack project")
    ap.add_argument("--version", action="version", version=__version__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("convert", help="convert a Fabric jar into a buildable native-mod project")
    c.add_argument("jar"); c.add_argument("-o", "--out", default="out")
    c.add_argument("--mc-versions", help='JSON array for the manifest, e.g. \'["1.26.*"]\'')
    c.add_argument("--symbols", help="symbol index (.txt), libminecraftpe.so, the zip containing it, or a *.symbols.json (default: the bundled DB)")
    c.add_argument("--mod-id")

    s = sub.add_parser("symbols", help="work with the Bedrock symbol index")
    ss = s.add_subparsers(dest="scmd", required=True)
    i = ss.add_parser("index", help="build symbols.txt from libminecraftpe.so / zip")
    i.add_argument("src"); i.add_argument("-o", "--out", default="symbols.txt")
    q = ss.add_parser("search", help="find mangled names containing all given identifiers")
    q.add_argument("index"); q.add_argument("names", nargs="+"); q.add_argument("-n", type=int, default=20)

    lt = sub.add_parser("live-test", help="generate the on-device proof project: hooks Item::getAttackDamage and adds N")
    lt.add_argument("-o", "--out", default="live-test"); lt.add_argument("--bonus", type=int, default=3)
    lt.add_argument("--mc-versions"); lt.add_argument("--symbols", help="a *.symbols.json (default: the bundled DB)")

    a = ap.parse_args(argv)
    if a.cmd == "live-test":
        from .livetest import generate
        r = generate(a.out, a.bonus, a.mc_versions, a.symbols)
        print(json.dumps(r, indent=2)); print(f"\nRead {r['out']}/LIVE_TEST.md, then build (push to GitHub: live-test workflow, or scripts/package.ps1).")
    elif a.cmd == "convert":
        from .generator import convert
        r = convert(a.jar, a.out, a.mc_versions, a.symbols, a.mod_id)
        print(json.dumps(r, indent=2))
        print(f"\nNext: read {r['out']}/CONVERSION_REPORT.md, then build (see README).")
    else:
        from .symbols import SymbolIndex, build_index
        if a.scmd == "index":
            syms = build_index(a.src)
            open(a.out, "w").write("\n".join(syms) + "\n")
            print(f"{len(syms)} symbols -> {a.out}")
        else:
            for s_ in SymbolIndex.load(a.index).search(*a.names, limit=a.n):
                print(s_)
    return 0


if __name__ == "__main__":
    sys.exit(main())
