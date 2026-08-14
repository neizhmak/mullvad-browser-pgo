#!/usr/bin/env python3
"""Resolve the immutable identity of the overlay-built PGO Rust sysroot."""
import argparse, hashlib, json, pathlib, subprocess


def sha(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda:f.read(1024*1024),b''): h.update(block)
    return h.hexdigest()

def show(upstream, key, pgo=True):
    cmd=[str(upstream/'rbm/rbm'),'showconf','rust',key,'--target','alpha','--target','mullvadbrowser-windows-x86_64']
    if pgo: cmd += ['--target','pgo-generate']
    return subprocess.check_output(cmd,cwd=upstream,text=True).strip()

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--upstream',type=pathlib.Path,required=True); ap.add_argument('--output',type=pathlib.Path,required=True); a=ap.parse_args()
    root=pathlib.Path(__file__).resolve().parents[1]
    lock=json.loads((root/'upstream.lock.json').read_text())
    mingw=[]
    for path in sorted((a.upstream/'out/mingw-w64-clang').glob('**/*')):
        if path.is_file(): mingw.append({'path':str(path.relative_to(a.upstream)),'sha256':sha(path),'size':path.stat().st_size})
    if not mingw: raise SystemExit('missing pinned mingw-w64-clang dependency')
    normal=show(a.upstream,'filename',False); pgo=show(a.upstream,'filename')
    if normal == pgo or '-profiler' not in pgo: raise SystemExit('PGO Rust output identity is not distinct from official Rust')
    data={'schema':1,'kind':'firefox-cross-pgo-rust','upstream':lock,
          'rust':{'version':show(a.upstream,'version'),'source_inputs':show(a.upstream,'input_files'),'rbm_target':'alpha,mullvadbrowser-windows-x86_64,pgo-generate','output_filename':pgo,'official_output_filename':normal,'config_sha256':sha(a.upstream/'projects/rust/config'),'build_sha256':sha(a.upstream/'projects/rust/build')},
          'overlay':{'path':'patches/firefox-pgo-generate.patch','sha256':sha(root/'patches/firefox-pgo-generate.patch')},
          'mingw_w64_clang':mingw}
    a.output.parent.mkdir(parents=True,exist_ok=True); a.output.write_text(json.dumps(data,indent=2,sort_keys=True)+'\n')
    print(json.dumps(data,indent=2,sort_keys=True))
if __name__=='__main__': main()
