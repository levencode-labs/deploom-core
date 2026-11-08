#!/usr/bin/env python3
"""Release only the owning public Core/MCP repository; never migrated projects."""
from __future__ import annotations
import argparse
from contextlib import contextmanager
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import tomllib
import urllib.error
import urllib.request
import uuid

REPOSITORIES={'deploom-core':'levencode-labs/deploom-core','deploom-mcp':'levencode-labs/deploom-mcp'}
VERSION=re.compile(r'^[0-9]+\.[0-9]+\.[0-9]+$')
class ReleaseError(RuntimeError):pass

def git(root,*args,check=True):
    r=subprocess.run(['git','-C',str(root),*args],capture_output=True,text=True,timeout=120)
    if check and r.returncode:raise ReleaseError('GIT_FAILED: '+args[0])
    return r.stdout.rstrip('\r\n') if check else r

def digest(raw):return hashlib.sha256(raw).hexdigest()

def plain(root,path):
    p=root/path
    if p.is_symlink() or not p.resolve().is_relative_to(root.resolve()):raise ReleaseError('UNSAFE_RELEASE_PATH')
    for parent in p.parents:
        if parent==root:break
        if parent.is_symlink():raise ReleaseError('UNSAFE_RELEASE_PARENT')
    return p

def atomic(path,raw,*,staging=None):
    if path.is_symlink():raise ReleaseError('UNSAFE_RELEASE_DESTINATION')
    temp=(staging or path.parent)/(path.name+'.component-release-'+uuid.uuid4().hex+'.tmp')
    if temp.exists() or temp.is_symlink():raise ReleaseError('RELEASE_TEMP_EXISTS')
    temp.write_bytes(raw);os.replace(temp,path)

def package(root):
    p=tomllib.loads(plain(root,'pyproject.toml').read_text(encoding='utf-8-sig'))['project']
    if p['name'] not in REPOSITORIES or not VERSION.fullmatch(p['version']):raise ReleaseError('UNSUPPORTED_RELEASE_PROJECT')
    return p['name'],p['version']

def inspect(root):
    root=Path(root).resolve();name,version=package(root)
    if Path(git(root,'rev-parse','--show-toplevel')).resolve()!=root:raise ReleaseError('WRONG_REPOSITORY_ROOT')
    if git(root,'branch','--show-current')!='main':raise ReleaseError('RELEASE_REQUIRES_MAIN')
    if git(root,'remote','get-url','origin')!='git@github.com:'+REPOSITORIES[name]+'.git':raise ReleaseError('UNEXPECTED_PUBLIC_SSH_ORIGIN')
    return {'repository':REPOSITORIES[name],'package':name,'version':version,'head':git(root,'rev-parse','HEAD')}

def version_files(name):
    return ['pyproject.toml']+(['src/deploom_mcp/__init__.py','release-manifest.json'] if name=='deploom-mcp' else [])

def replace_version(raw,path,old,new):
    text=raw.decode('utf-8')
    patterns={'pyproject.toml':r'(?m)^(version\s*=\s*")'+re.escape(old)+r'("\s*)$',
        'src/deploom_mcp/__init__.py':r'(?m)^(__version__\s*=\s*")'+re.escape(old)+r'("\s*)$',
        'release-manifest.json':r'("mcpVersion"\s*:\s*")'+re.escape(old)+r'(")'}
    text,count=re.subn(patterns[path],lambda m:m[1]+new+m[2],text)
    if count!=1:raise ReleaseError('VERSION_REPLACEMENT_NOT_UNIQUE: '+path)
    return text.encode('utf-8')

def changes(root,state):
    result={}
    if set(state['files'])!=set(version_files(state['package'])) or not re.fullmatch('[0-9a-f]{40}',state['base']):raise ReleaseError('INVALID_RELEASE_STATE_FILES')
    for path in version_files(state['package']):
        row=state['files'][path]
        before=base64.b64decode(row['before'],validate=True);after=base64.b64decode(row['after'],validate=True)
        if (digest(before)!=row['beforeSha256'] or digest(after)!=row['afterSha256']
                or replace_version(before,path,state['oldVersion'],state['version'])!=after):
            raise ReleaseError('INVALID_VERSION_EDIT_STATE')
        original=subprocess.run(['git','-C',str(root),'show',state['base']+':'+path],capture_output=True,timeout=30)
        if original.returncode or original.stdout.replace(b'\r\n',b'\n')!=before.replace(b'\r\n',b'\n'):
            raise ReleaseError('VERSION_STATE_DIFFERS_FROM_SOURCE_COMMIT')
        result[path]=(before,after)
    return result

def dirty_paths(root):
    rows=git(root,'-c','core.quotepath=false','status','--porcelain','--untracked-files=all').splitlines()
    return {row[3:] for row in rows}

def state_directory(root):
    p=plain(root,'.component-release');p.mkdir(exist_ok=True)
    if p.is_symlink():raise ReleaseError('UNSAFE_RELEASE_STATE')
    return p

@contextmanager
def release_lock(root):
    path=plain(root,'.component-release/owner.lock');state_directory(root)
    if path.is_symlink():raise ReleaseError('UNSAFE_RELEASE_LOCK')
    with path.open('a+b') as stream:
        stream.seek(0,2)
        if stream.tell()==0:stream.write(b'0');stream.flush()
        stream.seek(0)
        try:
            if os.name=='nt':
                import msvcrt
                msvcrt.locking(stream.fileno(),msvcrt.LK_NBLCK,1)
            else:
                import fcntl
                fcntl.flock(stream.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
        except OSError:raise ReleaseError('ANOTHER_RELEASE_PROCESS_OWNS_STATE') from None
        try:yield
        finally:
            stream.seek(0)
            if os.name=='nt':msvcrt.locking(stream.fileno(),msvcrt.LK_UNLCK,1)
            else:fcntl.flock(stream.fileno(),fcntl.LOCK_UN)

def save_state(root,state):
    folder=state_directory(root);raw=(json.dumps(state,sort_keys=True,indent=2)+'\n').encode()
    atomic(folder/(state['tag']+'.json'),raw)
    atomic(folder/'active.json',raw)

def prepare(root,tag=None,new_release=False):
    info=inspect(root);folder=state_directory(root);active=plain(root,'.component-release/active.json')
    state=json.loads(active.read_bytes()) if active.exists() else None
    if state is not None:
        if (state.get('schemaVersion')!=1 or state.get('repository')!=info['repository']
                or state.get('package')!=info['package'] or not VERSION.fullmatch(state.get('version',''))
                or state.get('tag')!='v'+state['version']):raise ReleaseError('INVALID_RELEASE_STATE')
        same_head=info['head'] in {state.get('base'),state.get('commit')}
        recovered=(git(root,'rev-parse','HEAD^',check=False).stdout.strip()==state.get('base')
            and git(root,'log','-1','--pretty=%s')=='chore: release '+state['tag'])
        if same_head or recovered:
            if tag and tag!=state['tag']:raise ReleaseError('PENDING_RELEASE_USE_SAME_TAG')
            return state
        if not new_release or state.get('phase') not in {'PUSHED','PUBLISHED'}:
            raise ReleaseError('SOURCE_CHANGED_USE_NEW_RELEASE_AFTER_REVIEWING_PREVIOUS_RUN')
    if dirty_paths(root):raise ReleaseError('DIRTY_WORKTREE_COMMIT_AND_MERGE_SOURCE_FIRST')
    if git(root,'rev-parse','refs/remotes/origin/main')!=info['head']:raise ReleaseError('MAIN_NOT_SYNCED_WITH_ORIGIN')
    major,minor,patch=map(int,info['version'].split('.'));target=f'{major}.{minor}.{patch+1}'
    if tag and tag!='v'+target:raise ReleaseError('NEW_RELEASE_REQUIRES_NEXT_PATCH_TAG')
    state={'schemaVersion':1,'repository':info['repository'],'package':info['package'],
        'base':info['head'],'oldVersion':info['version'],'version':target,'tag':'v'+target,'phase':'PREPARED'}
    files={}
    for path in version_files(info['package']):
        before=plain(root,path).read_bytes();after=replace_version(before,path,info['version'],target)
        files[path]={'before':base64.b64encode(before).decode(),'after':base64.b64encode(after).decode(),
            'beforeSha256':digest(before),'afterSha256':digest(after)}
    state['files']=files
    save_state(root,state);return state

def commit_version(root,state):
    edits=changes(root,state);head=git(root,'rev-parse','HEAD')
    if head==state['base']:
        if not dirty_paths(root).issubset(edits):raise ReleaseError('UNRELATED_CHANGES_PRESERVED')
        for path,(before,after) in edits.items():
            p=plain(root,path);raw=p.read_bytes()
            if raw not in (before,after):raise ReleaseError('VERSION_FILE_CHANGED_BY_OTHER_WORK')
        for path,(before,after) in edits.items():
            p=plain(root,path)
            if p.read_bytes()==before:atomic(p,after,staging=state_directory(root))
        if state['package']=='deploom-mcp':
            r=subprocess.run([sys.executable,'scripts/update_release_manifest.py','--check'],cwd=root,timeout=60)
            if r.returncode:raise ReleaseError('MCP_CORE_SKILL_OR_MANIFEST_UNPROVEN')
        git(root,'add','--',*edits)
        if set(git(root,'diff','--cached','--name-only').splitlines())!=set(edits):raise ReleaseError('UNEXPECTED_STAGED_RELEASE_FILES')
        git(root,'commit','-m','chore: release '+state['tag'])
        head=git(root,'rev-parse','HEAD')
    if (git(root,'rev-parse',head+'^')!=state['base']
            or git(root,'log','-1','--pretty=%s')!='chore: release '+state['tag']
            or set(git(root,'diff-tree','--no-commit-id','--name-only','-r',head).splitlines())!=set(edits)
            or any(plain(root,p).read_bytes()!=after for p,(_,after) in edits.items())
            or dirty_paths(root)):raise ReleaseError('RELEASE_COMMIT_OR_WORKTREE_CHANGED')
    state.update(commit=head,phase='VERSION_COMMITTED');save_state(root,state);return head

def push_release(root,state):
    info=inspect(root)
    if info['head']!=state['commit'] or info['version']!=state['version'] or dirty_paths(root):raise ReleaseError('RELEASE_SOURCE_CHANGED')
    git(root,'fetch','--no-recurse-submodules','origin','main')
    remote=git(root,'rev-parse','FETCH_HEAD')
    refs=git(root,'ls-remote','--tags','origin','refs/tags/'+state['tag'],'refs/tags/'+state['tag']+'^{}')
    rows={line.split()[1]:line.split()[0] for line in refs.splitlines()}
    target=rows.get('refs/tags/'+state['tag']+'^{}') or rows.get('refs/tags/'+state['tag'])
    if target is not None and target!=state['commit']:raise ReleaseError('IMMUTABLE_REMOTE_TAG_CONFLICT')
    if remote not in {state['base'],state['commit']}:
        if not target or git(root,'merge-base','--is-ancestor',state['commit'],remote,check=False).returncode:
            raise ReleaseError('REMOTE_MAIN_CHANGED_NO_FORCE_PUSH')
    local=git(root,'rev-parse','--verify','refs/tags/'+state['tag'],check=False)
    if local.returncode:
        if target:git(root,'fetch','--no-recurse-submodules','origin','refs/tags/'+state['tag']+':refs/tags/'+state['tag'])
        else:git(root,'tag','-a',state['tag'],state['commit'],'-m','Release '+state['tag'])
    if git(root,'rev-parse','refs/tags/'+state['tag']+'^{commit}')!=state['commit']:raise ReleaseError('IMMUTABLE_LOCAL_TAG_CONFLICT')
    tag_object=git(root,'rev-parse','refs/tags/'+state['tag'])
    if target and rows.get('refs/tags/'+state['tag'])!=tag_object:raise ReleaseError('REMOTE_TAG_OBJECT_CONFLICT')
    if not target:
        git(root,'push','--atomic','origin',state['commit']+':refs/heads/main','refs/tags/'+state['tag'])
    proof=git(root,'ls-remote','origin','refs/heads/main','refs/tags/'+state['tag'],'refs/tags/'+state['tag']+'^{}')
    proof={line.split()[1]:line.split()[0] for line in proof.splitlines()}
    if (proof.get('refs/tags/'+state['tag'])!=tag_object
            or proof.get('refs/tags/'+state['tag']+'^{}')!=state['commit']):raise ReleaseError('REMOTE_PUBLICATION_REFS_UNCONFIRMED')
    git(root,'fetch','--no-recurse-submodules','origin','main')
    remote=git(root,'rev-parse','FETCH_HEAD')
    if remote!=proof.get('refs/heads/main') or git(root,'merge-base','--is-ancestor',state['commit'],remote,check=False).returncode:
        raise ReleaseError('REMOTE_RELEASE_ANCESTRY_UNCONFIRMED')
    state.update(phase='PUSHED',tagObject=tag_object,remoteMain=remote);save_state(root,state)
    return {'status':'PUSHED_AWAITING_WORKFLOW','tag':state['tag'],'commit':state['commit'],
        'actions':'https://github.com/'+state['repository']+'/actions/workflows/release.yml'}

def wait_release(root,state,minutes):
    deadline=time.monotonic()+minutes*60
    url='https://api.github.com/repos/'+state['repository']+'/releases/tags/'+state['tag']
    while time.monotonic()<deadline:
        try:
            req=urllib.request.Request(url,headers={'Accept':'application/vnd.github+json','User-Agent':'DepLoom-component-release'})
            with urllib.request.urlopen(req,timeout=10) as response:data=json.load(response)
            expected={state['package'].replace('-','_')+'-'+state['version']+'-py3-none-any.whl',state['package'].replace('-','_')+'-'+state['version']+'.tar.gz','RELEASE-EVIDENCE.json','SHA256SUMS.txt'}
            if (data.get('tag_name')==state['tag'] and not data.get('draft') and len(data.get('assets',[]))==4 and {a.get('name') for a in data['assets']}==expected
                    and all(a.get('state')=='uploaded' and re.fullmatch(r'sha256:[0-9a-f]{64}',a.get('digest','')) for a in data['assets'])):
                request=urllib.request.Request('https://api.github.com/repos/'+state['repository']+'/actions/workflows/release.yml/runs?head_sha='+state['commit']+'&per_page=10',headers={'Accept':'application/vnd.github+json','User-Agent':'DepLoom-component-release'})
                with urllib.request.urlopen(request,timeout=10) as response:runs=json.load(response)['workflow_runs']
                runs=[r for r in runs if r['head_sha']==state['commit']]
                latest=max(runs,key=lambda r:r['id']) if runs else None
                if latest and latest['status']=='completed':
                    if latest['conclusion']!='success':raise ReleaseError('RELEASE_WORKFLOW_NOT_GREEN')
                    state['phase']='PUBLISHED';save_state(root,state);return {'status':'PUBLISHED','tag':state['tag'],'url':data['html_url']}
        except urllib.error.HTTPError as exc:
            if exc.code!=404:raise ReleaseError('PUBLIC_STATUS_UNAVAILABLE_USE_ACTIONS_URL') from None
        except (OSError,ValueError):raise ReleaseError('PUBLIC_STATUS_UNAVAILABLE_USE_ACTIONS_URL') from None
        time.sleep(min(30,max(0,deadline-time.monotonic())))
    raise ReleaseError('PUBLICATION_NOT_CONFIRMED_NO_NEW_VERSION_CREATED')

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tag');parser.add_argument('--new-release',action='store_true')
    parser.add_argument('--wait-minutes',type=int,default=0);parser.add_argument('--dry-run',action='store_true')
    parser.add_argument('--wheel-output',action='store_true')
    args=parser.parse_args(argv);root=Path(__file__).resolve().parents[1]
    try:
        if sys.version_info[:2] not in {(3,12),(3,13)}:raise ReleaseError('PYTHON_3_12_OR_3_13_REQUIRED')
        if args.wheel_output:
            name,version=package(root);wheel='dist/'+name.replace('-','_')+'-'+version+'-py3-none-any.whl'
            if not (root/wheel).is_file():raise ReleaseError('EXPECTED_WHEEL_MISSING')
            with open(os.environ['GITHUB_OUTPUT'],'a',encoding='utf8') as stream:stream.write('wheel='+wheel+'\n')
            return 0
        if not 0<=args.wait_minutes<=30:raise ReleaseError('INVALID_WAIT_BUDGET')
        info=inspect(root)
        if args.dry_run:print(json.dumps({'status':'READ_ONLY_RELEASE_PREFLIGHT','source':info,'dirty':bool(dirty_paths(root))}));return 0
        with release_lock(root):
            git(root,'fetch','--no-recurse-submodules','origin','main')
            state=prepare(root,args.tag,args.new_release)
            if state['phase']=='PUBLISHED':print(json.dumps({'status':'ALREADY_PUBLISHED','tag':state['tag'],'commit':state['commit']}));return 0
            if state['phase'] not in {'PUSHED'}:commit_version(root,state)
            result=push_release(root,state)
            if args.wait_minutes:result=wait_release(root,state,args.wait_minutes)
            print(json.dumps(result));return 0
    except (ReleaseError,OSError,ValueError,KeyError,subprocess.SubprocessError) as exc:
        print('Release stopped: '+str(exc),file=sys.stderr);return 1
if __name__=='__main__':raise SystemExit(main())
