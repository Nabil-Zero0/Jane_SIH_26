import os, glob, re

app_dir = r'frontend/src/app'
pages = glob.glob(os.path.join(app_dir, '**', 'page.tsx'), recursive=True)

report = {}

for p in sorted(pages):
    rel_p = os.path.relpath(p, app_dir)
    with open(p, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Check imports
    imports = re.findall(r'import\s+.*\s+from\s+["\']([^"\']+)["\']', content)
    
    # Check fetch calls
    fetches = re.findall(r'fetch\s*\(\s*["\'`]([^"\'`]+)["\'`]', content)
    template_fetches = re.findall(r'fetch\s*\(\s*`([^`]+)`', content)
    all_fetches = sorted(list(set(fetches + template_fetches)))
    
    # If no fetch, check if it imports another component from components/
    comp_fetches = []
    for imp in imports:
        if imp.startswith("@/components/") or imp.startswith("../"):
            comp_path = imp.replace("@/", "frontend/src/") + ".tsx"
            if os.path.exists(comp_path):
                with open(comp_path, 'r', encoding='utf-8') as cf:
                    ccontent = cf.read()
                cfetches = re.findall(r'fetch\s*\(\s*["\'`]([^"\'`]+)["\'`]', ccontent)
                ctemplate = re.findall(r'fetch\s*\(\s*`([^`]+)`', ccontent)
                for f in cfetches + ctemplate:
                    comp_fetches.append(f"{f} (via {imp})")
    
    report[rel_p] = {
        "file": p,
        "fetches": all_fetches,
        "comp_fetches": sorted(list(set(comp_fetches)))
    }

for k, v in report.items():
    print(f"=== {k} ===")
    if v['fetches']:
        for f in v['fetches']:
            print(f"  FETCH: {f}")
    if v['comp_fetches']:
        for f in v['comp_fetches']:
            print(f"  COMP_FETCH: {f}")
    if not v['fetches'] and not v['comp_fetches']:
        print("  NO FETCH (Static / Client-only)")
