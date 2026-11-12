# Trie les résultats Trivy : une ligne TSV par faille, avec portée (prod/dev) et chaîne d'origine.
import json, sys, os, glob, re
repo, jpath, src, label = sys.argv[1:5]
tmp = os.environ.get("RUNNER_TEMP", "/tmp")

chains = {}
for f in glob.glob(os.path.join(tmp, "chains", "*.tsv")):
    for line in open(f, encoding="utf-8"):
        parts = line.rstrip("\n").split("\t")
        if len(parts) == 3:
            chains.setdefault(parts[2], set()).add(parts[1])

npm_cache = {}
def npm_info(lockpath):
    if lockpath in npm_cache:
        return npm_cache[lockpath]
    try:
        lock = json.load(open(lockpath, encoding="utf-8"))
    except Exception:
        npm_cache[lockpath] = None
        return None
    pk = lock.get("packages", {})
    def resolve(frm, name):
        base = frm
        while True:
            cand = (base + "/" if base else "") + "node_modules/" + name
            if cand in pk:
                return cand
            if not base:
                return None
            i = base.rfind("/node_modules/")
            if i >= 0:
                base = base[:i]
            elif base.startswith("node_modules/"):
                base = ""
            else:
                base = ""
    starts = []
    for path, e in pk.items():
        if path == "" or ("node_modules/" not in path):
            pre = "" if path == "" else path + ">"
            for k in ("dependencies", "devDependencies", "optionalDependencies"):
                for n in (e.get(k) or {}):
                    starts.append((pre + n, path, n))
    reach = {}
    for label_d, frm, n in starts:
        s = resolve(frm, n)
        if not s:
            continue
        stack, seen = [s], {s}
        while stack:
            p = stack.pop()
            reach.setdefault(p, set()).add(label_d)
            e = pk.get(p, {})
            if e.get("link"):
                t = e.get("resolved")
                if t in pk and t not in seen:
                    seen.add(t); stack.append(t)
                continue
            for k in ("dependencies", "optionalDependencies", "peerDependencies"):
                for dn in (e.get(k) or {}):
                    q = resolve(p, dn)
                    if q and q not in seen:
                        seen.add(q); stack.append(q)
    npm_cache[lockpath] = (pk, reach)
    return npm_cache[lockpath]

def pub_info(lockpath):
    info, cur = {}, None
    try:
        for line in open(lockpath, encoding="utf-8"):
            m = re.match(r"^  ([A-Za-z0-9_]+):\s*$", line)
            if m:
                cur = m.group(1); continue
            m = re.match(r'^    dependency:\s*"?([^"\n]+)"?', line)
            if m and cur:
                info[cur] = m.group(1)
    except Exception:
        pass
    return info

d = json.load(open(jpath, encoding="utf-8"))
counts = {}
for r in d.get("Results", []) or []:
    target = r.get("Target", "")
    typ = r.get("Type", "")
    shown = (label + ":" if label else "") + target
    for v in r.get("Vulnerabilities", []) or []:
        name = v.get("PkgName", ""); ver = v.get("InstalledVersion", "")
        scope, chain = "", ""
        if typ == "npm" and label == "":
            info = npm_info(os.path.join(src, target))
            if info:
                pk, reach = info
                paths = [p for p, e in pk.items() if (p == "node_modules/" + name or p.endswith("/node_modules/" + name)) and e.get("version") == ver]
                if paths:
                    devs = [bool(pk[p].get("dev")) for p in paths]
                    scope = "dev" if all(devs) else "prod"
                    via = set()
                    for p in paths:
                        via |= reach.get(p, set())
                    chain = ",".join(sorted(via)[:6])
        elif typ == "gradle":
            scope = "release-apk"
            chain = ",".join(sorted(chains.get(name, set()))[:6])
        elif typ == "pub":
            lp = os.path.join(src, target)
            scope = pub_info(lp).get(name, "")
        elif v.get("PkgPath"):
            chain = v.get("PkgPath")
        if not scope and label.startswith("image"):
            scope = "image"
        title = (v.get("Title") or "").replace("\t", " ").replace("\n", " ")[:110]
        sev = v.get("Severity", "")
        counts[(shown, sev)] = counts.get((shown, sev), 0) + 1
        print("\t".join(["VULN", repo, shown, name, ver, sev, v.get("VulnerabilityID", ""),
                         v.get("FixedVersion", "") or "-", title, scope or "-", chain or "-"]))
for (t, s), n in sorted(counts.items()):
    print(f"RESUME\t{repo}\t{t}\t{s}\t{n}")
print(f"CIBLES\t{repo}\t" + " | ".join(f"{x.get('Target')} ({x.get('Type')})" for x in d.get("Results", []) or []))
