import os, re, sys
from pathlib import Path
from collections import defaultdict
import argparse
import csv
import time

CODE_EXTS = {".c",".h",".cpp",".hpp",".java",".py",".js",".ts"}

# ---------- File utils ----------
def iter_code_files(root: Path):
    for p in root.rglob("*"):
        if p.is_file() and p.suffix.lower() in CODE_EXTS:
            yield p

def read_text(p: Path):
    try:
        return p.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""

# ---------- Language-aware stripping of comments & strings ----------
# (fast regex approximations; good enough for measurement instruments)
RE_CPP_LINE = re.compile(r"//.*?$", re.MULTILINE)
RE_CPP_BLOCK = re.compile(r"/\*.*?\*/", re.DOTALL)
RE_PY_TRIPLE = re.compile(r"('{3}.*?'{3}|\"{3}.*?\"{3})", re.DOTALL)
RE_STR = re.compile(r"(\'(?:\\.|[^\\'])*\'|\"(?:\\.|[^\\\"])*\")", re.DOTALL)
RE_PY_LINE = re.compile(r"#.*?$", re.MULTILINE)

def strip_code(text: str, ext: str) -> str:
    t = text
    if ext in {".c",".h",".cpp",".hpp",".java",".js",".ts"}:
        t = RE_CPP_BLOCK.sub("", t)
        t = RE_CPP_LINE.sub("", t)
        t = RE_STR.sub('""', t)
    elif ext == ".py":
        t = RE_PY_TRIPLE.sub("", t)
        t = RE_PY_LINE.sub("", t)
        t = RE_STR.sub('""', t)
    return t

# ---------- LOC ----------
def physical_loc(text: str) -> int:
    return 0 if not text else len(text.splitlines())

def logical_loc(clean_text: str, ext: str) -> int:
    lines = [ln.strip() for ln in clean_text.splitlines()]
    # ignore empty and brace-only lines (common in C/JS/Java)
    return sum(1 for ln in lines if ln and ln not in {"{","}","};"})

# ---------- Cyclomatic complexity (file aggregate) ----------
KW_WORD = re.compile(r"\b(if|for|while|case|catch)\b")
OP_AND = re.compile(r"&&")
OP_OR  = re.compile(r"\|\|")
TERNARY_Q = re.compile(r"\?")
TERNARY_COLON = re.compile(r":")  # paired later (approx)

def cyclomatic_complexity(clean_text: str) -> int:
    base = 1
    k = len(KW_WORD.findall(clean_text))
    a = len(OP_AND.findall(clean_text))
    o = len(OP_OR.findall(clean_text))
    q = len(TERNARY_Q.findall(clean_text))
    c = len(TERNARY_COLON.findall(clean_text))
    # estimate ternary count as min(? , :) to avoid overcount when colons appear in other contexts
    ternary = min(q, c)
    return base + k + a + o + ternary

# ---------- Function extraction (very heuristic but safer) ----------
RE_FUNC_PY = re.compile(r"^\s*(async\s+)?def\s+([A-Za-z_]\w*)\s*\(", re.MULTILINE)
RE_FUNC_C_STYLE = re.compile(
    r"""^[ \t]*(?:template\s*<[^>]*>\s*)?    # C++ templates
        (?:[A-Za-z_][\w:<>\*\s\[\],&]+)?     # return type (optional to catch ctor)
        \s+([A-Za-z_]\w*)\s*\([^;{}]*\)\s*\{ # name(...) {   (skip prototypes)
    """,
    re.MULTILINE | re.VERBOSE,
)
# JS/TS: function foo(  or  foo( ... ) { within class/object  or  const foo = (...) => {
RE_FUNC_JS = re.compile(
    r"""^\s*(?:function\s+([A-Za-z_]\w*)\s*\(|      # function foo(
          (?:const|let|var)\s+([A-Za-z_]\w*)\s*=\s*\(.*?\)\s*=>\s*\{|  # const foo = (...) => {
          ([A-Za-z_]\w*)\s*\([^;{}]*\)\s*\{)         # method foo(...) {
    """,
    re.MULTILINE | re.VERBOSE,
)

def extract_functions(clean_text: str, ext: str):
    if ext == ".py":
        return {m.group(2) for m in RE_FUNC_PY.finditer(clean_text)}
    if ext in {".c",".h",".cpp",".hpp",".java"}:
        return {m.group(1) for m in RE_FUNC_C_STYLE.finditer(clean_text)}
    if ext in {".js",".ts"}:
        names = set()
        for m in RE_FUNC_JS.finditer(clean_text):
            for g in (1,2,3):
                if m.group(g):
                    names.add(m.group(g))
        return names
    return set()

# ---------- Imports / includes (file-level deps) ----------
RE_INC_LOCAL = re.compile(r'#\s*include\s*"([^"]+)"')
RE_PY_IMPORT = re.compile(r'^\s*(?:from\s+([\w\.]+)\s+import|import\s+([\w\.]+))', re.MULTILINE)
RE_JS_IMPORT = re.compile(r'^\s*import\s+.*?from\s*[\'"]([^\'"]+)[\'"]', re.MULTILINE)
RE_JS_REQUIRE = re.compile(r'require\s*\(\s*[\'"]([^\'"]+)[\'"]\s*\)')

# Remove definition lines so we don't treat them as calls
RE_FUNCDEF_PY_LINE = re.compile(r"^\s*(?:async\s+)?def\s+[A-Za-z_]\w*\s*\([^)]*\)\s*:\s*$", re.MULTILINE)

def strip_def_lines(clean_text: str, ext: str) -> str:
    t = clean_text
    if ext in {".c",".h",".cpp",".hpp",".java"}:
        t = RE_FUNC_C_STYLE.sub("{", t)   # replace signature with "{"
    elif ext == ".py":
        t = RE_FUNCDEF_PY_LINE.sub("", t)
    elif ext in {".js",".ts"}:
        t = RE_FUNC_JS.sub("{", t)
    return t


def extract_includes_and_imports(text: str, ext: str):
    deps = set()
    if ext in {".c",".h",".cpp",".hpp"}:
        deps |= set(RE_INC_LOCAL.findall(text))
    elif ext == ".py":
        for m in RE_PY_IMPORT.finditer(text):
            deps.add((m.group(1) or m.group(2)))
    elif ext in {".js",".ts"}:
        deps |= set(RE_JS_IMPORT.findall(text))
        deps |= set(RE_JS_REQUIRE.findall(text))
    elif ext == ".java":
        # map java imports to class names (last segment)
        for line in text.splitlines():
            line=line.strip()
            if line.startswith("import "):
                cls = line[len("import "):].rstrip(";").strip()
                if cls:
                    deps.add(cls)
    return deps

# ---------- Build index and dependency graph ----------
CALL_PATTERN_CACHE = {}

def call_regex(name: str):
    # skip tiny/common names to reduce false positives
    if len(name) < 3: 
        return None
    # cached compiled regex to match calls:  \bname\s*\(
    if name not in CALL_PATTERN_CACHE:
        CALL_PATTERN_CACHE[name] = re.compile(rf"\b{name}\s*\(")
    return CALL_PATTERN_CACHE[name]

def analyze_repo(root: Path, progress: bool=False, progress_every: int=500):
    files = list(iter_code_files(root))
    total = len(files)

    def tick(i, phase):
        if not progress:
            return
        if i % progress_every == 0 or i == total:
            pct = (i * 100) // total if total else 100
            print(f"[{phase}] {i}/{total} ({pct}%)")

    # ---- Pass 1: preprocess files ----
    t0 = time.perf_counter()
    info = {}
    for i, p in enumerate(files, 1):
        raw = read_text(p)
        ext = p.suffix.lower()
        cleaned = strip_code(raw, ext)
        info[p] = {
            "ext": ext,
            "raw": raw,
            "clean": cleaned,
            "physical_loc": physical_loc(raw),
            "logical_loc": logical_loc(cleaned, ext),
            "complexity": cyclomatic_complexity(cleaned),
            "funcs": extract_functions(cleaned, ext),
            "imports": extract_includes_and_imports(raw, ext),
            "call_text": strip_def_lines(cleaned, ext),
        }
        tick(i, "pass1: parse")

    # ---- Index: function -> files ----
    func_to_files = defaultdict(set)
    for p, d in info.items():
        for f in d["funcs"]:
            if f == "main":
                continue
            func_to_files[f].add(p)

    # ---- Pass 2: call-based edges ONLY (faster) ----
    edges_out = defaultdict(set)
    external_fanout = defaultdict(set)
    STOPWORDS = {
        "if","for","while","switch","return","sizeof","case","else","do","goto",
        "catch","try","new","delete"
    }

    # Optimization: for each file, extract its called names ONCE,
    # then resolve each name to an internal owner (unique) or mark external.
    name_call_regex = re.compile(r'\b([A-Za-z_]\w*)\s*\(')

    for i, (p, d) in enumerate(info.items(), 1):
        call_src = d["call_text"]

        called_names = set(name_call_regex.findall(call_src))
        # Remove obvious non-functions and self-defined ones
        called_names.difference_update(STOPWORDS)
        called_names.difference_update(d["funcs"])

        for name in called_names:
            owners = func_to_files.get(name)
            if owners:
                # internal: add edge only if unique owner and not self
                if len(owners) == 1:
                    owner = next(iter(owners))
                    if owner != p:
                        edges_out[p].add(owner)
                # else ambiguous name -> skip
            else:
                # unresolved -> external call
                external_fanout[p].add(name)

        tick(i, "pass2: edges")

    # ---- fan-in/fan-out ----
    fan_in = defaultdict(int)
    fan_out = {p: len(tgts) for p, tgts in edges_out.items()}
    for src, tgts in edges_out.items():
        for t in tgts:
            fan_in[t] += 1

    # ---- summarize ----
    results = {}
    for p in files:
        res = info[p]
        results[p] = {
            "physical_loc": res["physical_loc"],
            "logical_loc": res["logical_loc"],
            "complexity_file": res["complexity"],
            "fan_in": fan_in.get(p, 0),
            "fan_out": fan_out.get(p, 0),
            "external_fan_out": sorted(list(external_fanout.get(p, set()))) if p in external_fanout else [],
        }
    t1 = time.perf_counter()
    if progress:
        print(f"[done] analyzed {total} files in {t1 - t0:,.1f}s")
    return results


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("root", help="Path to repo root to analyze")
    p.add_argument("--verbose", "-v", action="store_true", help="Print per-file progress")
    p.add_argument("--csv", help="Write per-file metrics to this CSV path")
    p.add_argument("--progress", action="store_true", help="Show progress during analysis")
    p.add_argument("--progress-every", type=int, default=500, help="Update progress every N files")
    return p.parse_args()

def main():
    args = parse_args()
    root = Path(args.root).resolve()
    if not root.exists():
        print(f"[ERROR] Path does not exist: {root}")
        return

    # quick peek at what we’ll scan
    cand = list(iter_code_files(root))
    print(f"[INFO] Scanning: {root}")
    print(f"[INFO] File extensions considered: {sorted(CODE_EXTS)}")
    print(f"[INFO] Found {len(cand)} candidate source files")

    if len(cand) == 0:
        print("[WARN] No code files were found. "
              "Check the path and/or extensions. "
              "Try --verbose and confirm there are .py/.c/.cpp/.java/.js/.ts files.")
        return

    results = analyze_repo(root, progress=args.progress, progress_every=args.progress_every)

    total_phys = 0
    total_log = 0
    printed = 0

    for p, r in results.items():
        total_phys += r["physical_loc"]
        total_log  += r["logical_loc"]

        if args.verbose:
            ext_list = sorted(r.get("external_fan_out", []))
            print(f"{p} | phys={r['physical_loc']} log={r['logical_loc']} "
                f"CC(file)={r['complexity_file']} fan_in={r['fan_in']} fan_out={r['fan_out']} "
                f"external_fan_out={ext_list}")
            printed += 1

    if not args.verbose:
        # print a short sample so there’s always some output
        print("[INFO] Use --verbose to print every file. Sample:")
        shown = 0
        for p, r in results.items():
            print(f"{p} | phys={r['physical_loc']} log={r['logical_loc']} "
                  f"CC(file)={r['complexity_file']} fan_in={r['fan_in']} fan_out={r['fan_out']}")
            shown += 1
            if shown >= 10:
                print(f"[INFO] ...and {len(results)-shown} more files. Use --verbose to see all.")
                break
    
    if args.csv:
        out_path = Path(args.csv).resolve()
        with out_path.open("w", newline="", encoding="utf-8-sig") as f:
            w = csv.writer(f)
            w.writerow([
                "path","ext","physical_loc","logical_loc","complexity_file",
                "fan_in","fan_out","external_calls_count","external_calls"
            ])
            # stable order
            for pth in sorted(results.keys(), key=lambda x: str(x).lower()):
                r = results[pth]
                ext_calls = r.get("external_fan_out", [])
                w.writerow([
                    str(pth),
                    Path(pth).suffix.lower(),
                    r["physical_loc"],
                    r["logical_loc"],
                    r["complexity_file"],
                    r["fan_in"],
                    r["fan_out"],
                    len(ext_calls),
                    ";".join(ext_calls),
                ])
        print(f"[INFO] Wrote CSV: {out_path}")

    print(f"\nTOTAL physical LOC={total_phys} | TOTAL logical LOC={total_log}")

if __name__ == "__main__":
    main()
