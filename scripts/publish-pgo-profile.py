#!/usr/bin/env python3
"""Immutably publish a verified Stage 4A profile; commit registry last."""
import argparse, hashlib, json, pathlib, subprocess

def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def run(*args, capture=False):
    return subprocess.run(args, check=True, text=True, stdout=subprocess.PIPE if capture else None).stdout
def assets(repo, tag):
    data=json.loads(run('gh','release','view',tag,'--repo',repo,'--json','assets',capture=True))
    return {x['name']:x for x in data['assets']}
def main():
    p=argparse.ArgumentParser(); p.add_argument('--repository',required=True); p.add_argument('--release',required=True); p.add_argument('--directory',required=True); a=p.parse_args()
    d=pathlib.Path(a.directory); payload=[d/'merged.profdata',d/'jarlog',d/'provenance.json']; registry=d/'profile-registry.json'
    for f in payload:
        if not f.is_file() or not f.stat().st_size: raise SystemExit(f'missing/empty profile asset: {f}')
    current=assets(a.repository,a.release)
    if 'profile-registry.json' in current:
        remote=pathlib.Path('/tmp/pgo-published-registry.json'); run('gh','release','download',a.release,'--repo',a.repository,'--pattern','profile-registry.json','--output',str(remote))
        if sha(remote)!=sha(registry): raise SystemExit('conflicting verified profile already committed')
        print('Identical profile registry already committed; nothing to overwrite.'); return
    for f in payload:
        if f.name in current:
            remote=pathlib.Path('/tmp') / ('pgo-' + f.name)
            run('gh','release','download',a.release,'--repo',a.repository,'--pattern',f.name,'--output',str(remote))
            if sha(remote) != sha(f): raise SystemExit(f'incomplete conflicting publication contains {f.name}')
            print(f'Reusing identical interrupted-publication asset: {f.name}')
            continue
        run('gh','release','upload',a.release,str(f),'--repo',a.repository)
    # Registry is the commit marker and is deliberately uploaded last.
    run('gh','release','upload',a.release,str(registry),'--repo',a.repository)
if __name__=='__main__': main()
