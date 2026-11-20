#!/usr/bin/env python3
"""Exact-tag CI qualification and immutable GitHub release publication."""
from __future__ import annotations
import argparse
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import time
from component_release import package,REPOSITORIES,ReleaseError,git
ROOT=Path(__file__).resolve().parents[1]

def run(argv,*,cwd=ROOT,env=None,timeout=300,capture=False):
    result=subprocess.run(argv,cwd=cwd,env=env,timeout=timeout,capture_output=capture,text=True)
    if result.returncode:raise ReleaseError('RELEASE_COMMAND_FAILED: '+Path(argv[0]).name)
    return result.stdout if capture else None

def api(endpoint,*,method='GET',payload=None):
    args=['gh','api','--method',method,endpoint]
    if payload is not None:
        result=subprocess.run(args+['--input','-'],input=json.dumps(payload),capture_output=True,text=True,timeout=90)
        if result.returncode:raise ReleaseError('GITHUB_RELEASE_API_FAILED')
        return json.loads(result.stdout) if result.stdout.strip() else None
    return json.loads(run(args,capture=True,timeout=90))

def identity(tag):
    name,version=package(ROOT);repo=REPOSITORIES[name]
    if (os.environ.get('GITHUB_REPOSITORY')!=repo or tag!='v'+version
            or not re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+',tag)):
        raise ReleaseError('RELEASE_REPOSITORY_VERSION_TAG_MISMATCH')
    head=git(ROOT,'rev-parse','HEAD')
    if os.environ.get('GITHUB_SHA')!=head:raise ReleaseError('WORKFLOW_DEFINITION_NOT_FROM_TAG_COMMIT')
    if git(ROOT,'cat-file','-t','refs/tags/'+tag)!='tag':raise ReleaseError('ANNOTATED_RELEASE_TAG_REQUIRED')
    if git(ROOT,'rev-parse','refs/tags/'+tag+'^{commit}')!=head:raise ReleaseError('RELEASE_TAG_HEAD_MISMATCH')
    if git(ROOT,'merge-base','--is-ancestor',head,'origin/main',check=False).returncode:
        raise ReleaseError('RELEASE_NOT_IN_MAIN')
    tag_object=git(ROOT,'rev-parse','refs/tags/'+tag)
    if os.environ.get('EXPECTED_TAG_OBJECT',tag_object)!=tag_object:raise ReleaseError('TAG_OBJECT_CHANGED_DURING_RELEASE')
    return {'package':name,'version':version,'tag':tag,'repository':repo,'commit':head,'tagObject':tag_object}

def wait_main(tag):
    value=identity(tag);workflows=['ci.yml']+(['audit.yml'] if value['package']=='deploom-mcp' else [])
    deadline=time.monotonic()+1200;completed={}
    while time.monotonic()<deadline:
        for workflow in workflows:
            if workflow in completed:continue
            endpoint='repos/'+value['repository']+'/actions/workflows/'+workflow+'/runs?event=push&branch=main&head_sha='+value['commit']+'&per_page=10'
            rows=api(endpoint)['workflow_runs']
            rows=[r for r in rows if r['head_sha']==value['commit'] and r['event']=='push' and r['head_branch']=='main']
            if not rows:continue
            latest=max(rows,key=lambda r:r['id'])
            if latest['status']=='completed':
                if latest['conclusion']!='success':raise ReleaseError('REQUIRED_MAIN_CI_NOT_GREEN: '+latest['html_url'])
                completed[workflow]=latest['html_url']
        if len(completed)==len(workflows):
            out=Path(os.environ['GITHUB_OUTPUT'])
            with out.open('a',encoding='utf8') as stream:
                for k in ('commit','tag','version','tagObject'):stream.write(k+'='+value[k]+'\n')
                stream.write('ciRuns='+json.dumps(completed,sort_keys=True)+'\n')
            print(json.dumps({'status':'EXACT_MAIN_CI_GREEN','commit':value['commit'],'runs':completed}));return
        time.sleep(min(20,max(0,deadline-time.monotonic())))
    raise ReleaseError('REQUIRED_MAIN_CI_DEADLINE_NO_PUBLICATION')

def build_assets(tag):
    value=identity(tag);out=ROOT/'.component-release'/'ci-artifacts'
    if out.exists():raise ReleaseError('ARTIFACT_OUTPUT_EXISTS_DO_NOT_REBUILD_OVER_IT')
    out.mkdir(parents=True)
    run([sys.executable,'scripts/check-public-sanitization.py'])
    if value['package']=='deploom-mcp':
        run([sys.executable,'scripts/check_skill.py']);run([sys.executable,'scripts/update_release_manifest.py','--check'])
    run([sys.executable,'-m','build','--no-isolation','--outdir',str(out)])
    wheel,=out.glob('*.whl');sdist,=out.glob('*.tar.gz')
    if value['package']=='deploom-mcp':
        run([sys.executable,'scripts/smoke_stdio.py']);run([sys.executable,'scripts/smoke_wheel.py',str(wheel)])
    else:
        installed=ROOT/'.component-release'/'installed-core'
        run([sys.executable,'-m','pip','install','--no-deps','--no-index','--no-compile','--target',str(installed),str(wheel)])
        body="import pathlib,sys,importlib.metadata;import dependency_live_roadmap_generator as m;assert pathlib.Path(m.__file__).is_relative_to(pathlib.Path(sys.argv[1]));assert importlib.metadata.version('deploom-core')==sys.argv[2];import migration_documents as docs;assert pathlib.Path(docs.__file__).is_relative_to(pathlib.Path(sys.argv[1]));docs.check_catalogs();sys.argv=['deploom-core','--help'];m.main()"
        run([sys.executable,'-c',body,str(installed),value['version']],cwd=ROOT.parent,env={**os.environ,'PYTHONPATH':str(installed)})
    extracted=ROOT/'.component-release'/'sdist-source';extracted.mkdir()
    with tarfile.open(sdist) as archive:
        for row in archive.getmembers():
            if row.issym() or row.islnk() or not (extracted/row.name).resolve().is_relative_to(extracted.resolve()):
                raise ReleaseError('UNSAFE_SDIST_MEMBER')
        archive.extractall(extracted,filter='data')
    source,=extracted.iterdir();rebuilt=ROOT/'.component-release'/'rebuilt-wheel'
    run([sys.executable,'-m','build','--wheel','--no-isolation','--outdir',str(rebuilt)],cwd=source)
    rebuilt_wheel,=rebuilt.glob('*.whl')
    if value['package']=='deploom-mcp':run([sys.executable,'scripts/smoke_wheel.py',str(rebuilt_wheel)])
    else:
        second=ROOT/'.component-release'/'rebuilt-core-install'
        run([sys.executable,'-m','pip','install','--no-deps','--no-index','--no-compile','--target',str(second),str(rebuilt_wheel)])
        run([sys.executable,'-c',body,str(second),value['version']],cwd=ROOT.parent,env={**os.environ,'PYTHONPATH':str(second)})
    records=[{'name':p.name,'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'bytes':p.stat().st_size} for p in (wheel,sdist)]
    evidence={**value,'status':'EXACT_SOURCE_DISTRIBUTION_CHECKS_PASS','artifacts':records,
        'run':'https://github.com/'+value['repository']+'/actions/runs/'+os.environ['GITHUB_RUN_ID'],
        'mainCiRuns':json.loads(os.environ['REQUIRED_MAIN_CI_JSON']),'python':sys.version.split()[0],'buildTools':{x:importlib.metadata.version(x) for x in ('build','setuptools','wheel')},
        'scope':'Bounded component release; not a new real-project migration acceptance or universal speedup proof'}
    if value['package']=='deploom-mcp':evidence['corePin']=json.loads((ROOT/'release-manifest.json').read_bytes())['core']['revision']
    (out/'RELEASE-EVIDENCE.json').write_text(json.dumps(evidence,sort_keys=True,indent=2)+'\n',encoding='utf8')
    (out/'SHA256SUMS.txt').write_text(''.join(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+p.name+'\n' for p in sorted(out.iterdir())),encoding='utf8')
    with open(os.environ['GITHUB_OUTPUT'],'a',encoding='utf8') as stream:stream.write('manifest-sha='+hashlib.sha256((out/'SHA256SUMS.txt').read_bytes()).hexdigest()+'\n')
    print(json.dumps({'status':'QUALIFIED_RELEASE_ASSETS','names':sorted(p.name for p in out.iterdir())}))

def expected_assets(folder,value):
    names={value['package'].replace('-','_')+'-'+value['version']+'-py3-none-any.whl',
        value['package'].replace('-','_')+'-'+value['version']+'.tar.gz','RELEASE-EVIDENCE.json','SHA256SUMS.txt'}
    if {p.name for p in folder.iterdir()}!=names or any(p.is_symlink() or not p.is_file() for p in folder.iterdir()):
        raise ReleaseError('RELEASE_ASSET_SET_MISMATCH')
    evidence=json.loads((folder/'RELEASE-EVIDENCE.json').read_bytes())
    if any(evidence.get(k)!=value[k] for k in ('repository','package','version','tag','commit','tagObject')):
        raise ReleaseError('RELEASE_ASSET_SOURCE_MISMATCH')
    manifest={}
    for line in (folder/'SHA256SUMS.txt').read_text().splitlines():
        sha,name=line.split('  ',1)
        if name in manifest or name not in names or not re.fullmatch('[0-9a-f]{64}',sha):raise ReleaseError('RELEASE_CHECKSUM_MANIFEST_INVALID')
        manifest[name]=sha
    if set(manifest)!=names-{'SHA256SUMS.txt'}:raise ReleaseError('RELEASE_CHECKSUM_COVERAGE')
    result={p.name:{'size':p.stat().st_size,'digest':'sha256:'+hashlib.sha256(p.read_bytes()).hexdigest()} for p in folder.iterdir()}
    if any(result[name]['digest']!='sha256:'+sha for name,sha in manifest.items()):raise ReleaseError('RELEASE_ARTIFACT_CHANGED')
    return result

def reconcile_assets(existing,expected):
    found={}
    for row in existing:
        name=row['name']
        if name in found or name not in expected:raise ReleaseError('UNEXPECTED_OR_DUPLICATE_PUBLISHED_ASSET')
        found[name]=row
        if row.get('state')!='uploaded' or any(row.get(k)!=v for k,v in expected[name].items()):
            raise ReleaseError('IMMUTABLE_RELEASE_ASSET_CONFLICT: '+name)
    return sorted(set(expected)-set(found))

def remote_tag_matches(value):
    ref=api('repos/'+value['repository']+'/git/ref/tags/'+value['tag'])
    if ref.get('object',{}).get('type')!='tag' or ref['object'].get('sha')!=value['tagObject']:
        raise ReleaseError('REMOTE_ANNOTATED_TAG_CHANGED')
    tag=api('repos/'+value['repository']+'/git/tags/'+value['tagObject'])
    if tag.get('object',{}).get('type')!='commit' or tag['object'].get('sha')!=value['commit'] or tag.get('tag')!=value['tag']:
        raise ReleaseError('REMOTE_TAG_TARGET_CHANGED')

def find_release(repo,tag):
    # The tag endpoint excludes drafts. Authenticated list includes drafts.
    # Exhaust pagination before proving absence; an API failure must propagate.
    matches=[]
    for page in range(1,101):
        rows=api('repos/'+repo+'/releases?per_page=100&page='+str(page))
        matches.extend(row for row in rows if row.get('tag_name')==tag)
        if len(matches)>1:raise ReleaseError('DUPLICATE_RELEASE_TAG')
        if len(rows)<100:return matches[0] if matches else None
    raise ReleaseError('RELEASE_LOOKUP_PAGINATION_LIMIT')

def publish(tag,folder):
    value=identity(tag);folder=Path(folder).resolve()
    manifest_sha=os.environ.get('EXPECTED_MANIFEST_SHA256','');artifact_id=os.environ.get('RELEASE_ARTIFACT_ID','');bundle_sha=os.environ.get('RELEASE_ARTIFACT_DIGEST','')
    if not re.fullmatch('[0-9a-f]{64}',manifest_sha) or not artifact_id.isdigit() or not re.fullmatch('[0-9a-f]{64}',bundle_sha):raise ReleaseError('QUALIFIED_BUNDLE_IDENTITY_MISSING')
    if hashlib.sha256((folder/'SHA256SUMS.txt').read_bytes()).hexdigest()!=manifest_sha:raise ReleaseError('QUALIFIED_MANIFEST_CHANGED')
    bundle=api('repos/'+value['repository']+'/actions/artifacts/'+artifact_id)
    if (str(bundle.get('id'))!=artifact_id or bundle.get('expired') is not False
            or bundle.get('digest')!='sha256:'+bundle_sha or bundle.get('name')!='component-release-'+value['commit']
            or str(bundle.get('workflow_run',{}).get('id'))!=os.environ['GITHUB_RUN_ID']
            or bundle.get('workflow_run',{}).get('head_sha')!=value['commit']):raise ReleaseError('QUALIFIED_ARTIFACT_BUNDLE_MISMATCH')
    expected=expected_assets(folder,value)
    remote_tag_matches(value)
    repo=value['repository'];release=find_release(repo,tag)
    if release is None:
        release=api('repos/'+repo+'/releases',method='POST',payload={
            'tag_name':tag,'target_commitish':value['commit'],'draft':True,
            'name':value['package']+' '+value['version'],
            'body':'Exact source: '+value['commit']+'. See RELEASE-EVIDENCE.json and SHA256SUMS.txt. Component qualification does not replace real-project acceptance.'})
    if release.get('tag_name')!=tag or not isinstance(release.get('id'),int):raise ReleaseError('RELEASE_IDENTITY_MISMATCH')
    endpoint='repos/'+repo+'/releases/'+str(release['id'])
    release=api(endpoint)
    missing=reconcile_assets(release['assets'],expected)
    if missing and not release['draft']:raise ReleaseError('PUBLISHED_RELEASE_INCOMPLETE_NO_SILENT_MODIFICATION')
    for name in missing:run(['gh','api','--method','POST','https://uploads.github.com/repos/'+repo+'/releases/'+str(release['id'])+'/assets?name='+name,'-H','Content-Type: application/octet-stream','--input',str(folder/name)],capture=True)
    release=api(endpoint)
    if reconcile_assets(release['assets'],expected):raise ReleaseError('UPLOADED_ASSET_SET_INCOMPLETE')
    if release['draft']:api(endpoint,method='PATCH',payload={'draft':False,'make_latest':'true'})
    final=api(endpoint)
    if final['draft'] or reconcile_assets(final['assets'],expected):raise ReleaseError('PUBLICATION_NOT_CONFIRMED')
    remote_tag_matches(value)
    print(json.dumps({'status':'PUBLISHED','tag':tag,'commit':value['commit'],'url':final['html_url']}))

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('action',choices=['wait-main','build','publish']);p.add_argument('--tag',required=True);p.add_argument('--artifacts',default='release-artifacts');args=p.parse_args()
    try:
        if args.action=='wait-main':wait_main(args.tag)
        elif args.action=='build':build_assets(args.tag)
        else:publish(args.tag,args.artifacts)
        return 0
    except (OSError,ValueError,KeyError,ReleaseError,subprocess.SubprocessError) as exc:
        print('Release CI stopped: '+str(exc),file=sys.stderr);return 1
if __name__=='__main__':raise SystemExit(main())
