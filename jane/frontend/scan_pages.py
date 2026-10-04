import os, glob, re

app_dir = r'frontend/src/app'
pages = glob.glob(os.path.join(app_dir, '**', 'page.tsx'), recursive=True)

for p in sorted(pages):
    with open(p, 'r', encoding='utf-8') as f:
        content = f.read()
    fetches = re.findall(r'fetch\s*\(\s*["\'`]([^"\'`]+)["\'`]', content)
    # also look for template string fetches
    template_fetches = re.findall(r'fetch\s*\(\s*`([^`]+)`', content)
    rel_p = os.path.relpath(p, app_dir)
    print(f"=== {rel_p} ===")
    all_f = set(fetches + template_fetches)
    if all_f:
        for fetch in sorted(all_f):
            print(f"  FETCH: {fetch}")
    else:
        print("  NO FETCH FOUND")
