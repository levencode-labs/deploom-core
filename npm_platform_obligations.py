"""Explicit npm-v3 platform absence: archive-bound evidence, never npm-exit inference."""
from pathlib import Path, PurePosixPath
import base64,hashlib,json,re,os,shutil,tarfile,io
from semantic_version import NpmSpec,Version
from project_runtime import normalize_npm_range

class NpmPlatformEvidenceError(ValueError):pass

def _fail(message):raise NpmPlatformEvidenceError('NPM_PLATFORM_'+message)
def _sha(raw):return hashlib.sha256(raw).hexdigest()
def _digest(value):return _sha(json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode())
def _object(raw):
 def pairs(items):
  value={}
  for key,item in items:
   if key in value:_fail('DUPLICATE_JSON')
   value[key]=item
  return value
 try:
  value=json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda x:_fail('JSON_CONSTANT'))
 except (ValueError,UnicodeError) as exc:raise NpmPlatformEvidenceError('NPM_PLATFORM_JSON_UNPROVEN') from exc
 if not isinstance(value,dict):_fail('JSON_UNPROVEN')
 return value

def total_archive_budget(rules):
 limits=rules.get('resourceLimits')
 if limits is None:
  if 'resourceLimits' in rules:_fail('RESOURCE_LIMIT_SCHEMA')
  return 128*1024*1024
 if (not isinstance(limits,dict) or set(limits)!={'maxTotalArchiveBytes'}
   or type(limits['maxTotalArchiveBytes']) is not int
   or not 128*1024*1024<=limits['maxTotalArchiveBytes']<=256*1024*1024):_fail('RESOURCE_LIMIT_SCHEMA')
 return limits['maxTotalArchiveBytes']


def validate_rules_shape(rules):
 if (not isinstance(rules,dict) or set(rules) not in ({'schemaVersion','kind','host','artifacts'},{'schemaVersion','kind','host','artifacts','resourceLimits'})
   or type(rules['schemaVersion']) is not int or rules['schemaVersion']!=1
   or rules['kind'] not in {'NPM_V3_SRI_PLATFORM_ABSENCE_V1','NPM_V2_SRI_PLATFORM_ABSENCE_V1'}):_fail('RULE_SCHEMA')
 total_archive_budget(rules)
 host=rules['host']
 if (not isinstance(host,dict) or set(host)!={'platform','arch','nodeSha256'}
   or host['platform']!='win32' or host['arch'] not in ('x64','ia32','arm64')
   or not isinstance(host['nodeSha256'],str) or re.fullmatch('[0-9a-f]{64}',host['nodeSha256']) is None):_fail('HOST_SCHEMA')
 artifacts=rules['artifacts']
 if not isinstance(artifacts,list) or not 1<=len(artifacts)<=256:_fail('ARTIFACT_LIMIT')
 seen=set()
 for row in artifacts:
  if (not isinstance(row,dict) or set(row)!={'instance','archivePath'} or not isinstance(row['instance'],str)
    or row['instance'] in seen or not isinstance(row['archivePath'],str)
    or not Path(row['archivePath']).is_absolute()):_fail('ARTIFACT_SCHEMA')
  seen.add(row['instance'])
 return rules

def _file_sha256(path):
 with path.open('rb') as stream:
  return hashlib.file_digest(stream,'sha256').hexdigest()

def observe_node_host():
 from verification_process_supervisor import run_supervised
 if os.environ.get('NODE_OPTIONS') or os.environ.get('NODE_PATH'):_fail('EXTERNAL_NODE_LOADER')
 node=shutil.which('node')
 if not node:_fail('NODE_MISSING')
 path=Path(node).resolve();before=_file_sha256(path)
 result=run_supervised([str(path),'-p','JSON.stringify({platform:process.platform,arch:process.arch})'],Path.cwd(),timeout_seconds=10,max_output_bytes=4096)
 supervision=getattr(result,'supervision',None)
 if (result.returncode or getattr(supervision,'quality',None)!='guaranteed-tree'
   or getattr(supervision,'descendants_remaining',None)!=0 or _file_sha256(path)!=before):_fail('HOST_UNPROVEN')
 value=_object(result.stdout.encode())
 if set(value)!={'platform','arch'}:_fail('HOST_UNPROVEN')
 return {**value,'nodeSha256':before}

def _selectors(raw,actual):
 if raw is None:return True
 if (not isinstance(raw,list) or not raw or len(raw)>64
   or any(not isinstance(x,str) or re.fullmatch('!?[a-zA-Z0-9_+-]{1,40}',x) is None for x in raw)):_fail('SELECTOR_UNSUPPORTED')
 if len(set(raw))!=len(raw) or any('!'+x in raw for x in raw if not x.startswith('!')):_fail('SELECTOR_CONTRADICTORY')
 if 'any' in raw and raw!=['any']:_fail('SELECTOR_UNSUPPORTED')
 if '!'+actual in raw:return False
 positive=[x for x in raw if not x.startswith('!')]
 return not positive or actual in positive or 'any' in positive

def _parent(location):return location.rpartition('/node_modules/')[0] if '/node_modules/' in location else ''
def _resolve(graph,location,name,peer=False):
 if re.fullmatch(r'(?:@[A-Za-z0-9][A-Za-z0-9._-]*/)?[A-Za-z0-9][A-Za-z0-9._-]*',name) is None:_fail('EDGE_NAME')
 base=_parent(location) if peer else location
 while True:
  target=(base+'/' if base else '')+'node_modules/'+name
  if target in graph:return target
  if not base:return None
  base=_parent(base)

def _archive(path,row,canonical):
 path=Path(path)
 for part in [path,*path.parents]:
  if part.is_symlink() or (hasattr(part,'is_junction') and part.is_junction()):_fail('ARCHIVE_REPARSE')
 if not path.is_file() or path.stat().st_size>32*1024*1024:_fail('ARCHIVE_SIZE')
 raw=path.read_bytes();sri='sha512-'+base64.b64encode(hashlib.sha512(raw).digest()).decode()
 if row.get('integrity')!=sri:_fail('ARTIFACT_SRI_MISMATCH')
 manifest=None;total=0;count=0;root=None
 try:
  with tarfile.open(fileobj=io.BytesIO(raw),mode='r|gz') as archive:
   for member in archive:
    total+=member.size;count+=1
    if total>128*1024*1024 or count>10000:_fail('ARCHIVE_EXPANSION_LIMIT')
    parts=PurePosixPath(member.name).parts
    if (not parts or member.name.startswith('/') or '..' in parts
        or any(':' in part or chr(92) in part for part in parts)):_fail('ARCHIVE_ENTRY_PATH')
    if root is None:root=parts[0]
    if parts[0]!=root:_fail('ARCHIVE_ROOT_UNPROVEN')
    if len(parts)==2 and parts[1]=='package.json':
     if manifest is not None or not member.isfile() or member.size>1024*1024:_fail('MANIFEST_UNPROVEN')
     manifest=_object(archive.extractfile(member).read(1024*1024+1))
 except (tarfile.TarError,OSError) as exc:raise NpmPlatformEvidenceError('NPM_PLATFORM_ARCHIVE_UNPROVEN') from exc
 if not manifest or manifest.get('name')!=canonical or manifest.get('version')!=row.get('version'):_fail('ARTIFACT_IDENTITY')
 # Missing lock metadata is not assumed known: the archive supplies it. Existing
 # declarations MUST agree, so changing candidate os/cpu cannot manufacture absence.
 for key in ('os','cpu','libc'):
  if key in row and row[key]!=manifest.get(key):_fail('ARTIFACT_PLATFORM_MISMATCH')
 return manifest,{'archiveSha256':_sha(raw),'packageManifestDigest':_digest(manifest),'integrity':sri},len(raw)

def _v2_view_record(lock,location,record,*,allow_bundled=False):
 """Platform evidence must agree with npm-v2's compatible tree view."""
 parts=location.split('/node_modules/');parts[0]=parts[0].removeprefix('node_modules/')
 tree=lock.get('dependencies');other=None
 for name in parts:
  if re.fullmatch(r'(?:@[A-Za-z0-9][A-Za-z0-9._-]*/)?[A-Za-z0-9][A-Za-z0-9._-]*',name) is None:_fail('V2_INSTANCE_PATH')
  if not isinstance(tree,dict) or not isinstance(tree.get(name),dict):_fail('V2_VIEW_MISSING')
  other=tree[name];tree=other.get('dependencies',{})
 install=parts[-1];canonical=record.get('name',install)
 if not isinstance(canonical,str) or re.fullmatch(r'(?:@[A-Za-z0-9][A-Za-z0-9._-]*/)?[A-Za-z0-9][A-Za-z0-9._-]*',canonical) is None:_fail('V2_ALIAS_IDENTITY')
 expected_version=('npm:'+canonical+'@'+str(record.get('version'))) if canonical!=install else record.get('version')
 if other.get('version')!=expected_version:_fail('V2_VIEW_MISMATCH')
 if 'name' in other and other['name']!=canonical:_fail('V2_ALIAS_IDENTITY')
 for key in ('resolved','integrity','optional','dev','devOptional'):
  if other.get(key)!=record.get(key):_fail('V2_VIEW_MISMATCH')
 if record.get('link') or other.get('link'):_fail('V2_CONDITIONAL_OWNER_UNSUPPORTED')
 if not allow_bundled and (record.get('inBundle') or other.get('bundled')):_fail('V2_CONDITIONAL_OWNER_UNSUPPORTED')
 for row,flags in ((record,('optional','dev','devOptional','inBundle','link')),(other,('optional','dev','devOptional','bundled','link'))):
  if any(key in row and type(row[key]) is not bool for key in flags):_fail('V2_VIEW_FLAG_TYPE')
 if record.get('inBundle',False)!=other.get('bundled',False):_fail('V2_VIEW_MISMATCH')
 if any(not isinstance(record.get(key,{}),dict) for key in ('dependencies','optionalDependencies')):_fail('V2_VIEW_REQUIREMENTS_MISMATCH')
 if {**record.get('dependencies',{}),**record.get('optionalDependencies',{})}!=other.get('requires',{}):_fail('V2_VIEW_REQUIREMENTS_MISMATCH')
 return other

def _v2_consistent_graph(lock):
 graph=lock.get('packages');tree=lock.get('dependencies');seen=set();folded=set();pending=[('',tree)]
 if not isinstance(graph,dict) or '' not in graph:_fail('V2_VIEW_MISSING')
 if len({n.casefold() for n in graph if isinstance(n,str)})!=len(graph):_fail('V2_VIEW_MISMATCH')
 while pending:
  base,children=pending.pop()
  if not isinstance(children,dict):_fail('V2_VIEW_MISMATCH')
  for name,row in children.items():
   if not isinstance(name,str) or re.fullmatch(r'(?:@[A-Za-z0-9][A-Za-z0-9._-]*/)?[A-Za-z0-9][A-Za-z0-9._-]*',name) is None or not isinstance(row,dict):_fail('V2_VIEW_MISMATCH')
   path=(base+'/' if base else '')+'node_modules/'+name
   if path in seen or path.casefold() in folded or len(seen)>=10000:_fail('V2_VIEW_MISMATCH')
   seen.add(path);folded.add(path.casefold());pending.append((path,row.get('dependencies',{})))
 expected=set(graph)-{''}
 if expected-seen:_fail('V2_VIEW_MISSING')
 if seen-expected:_fail('V2_VIEW_MISMATCH')
 for path in seen:
  if not isinstance(graph[path],dict):_fail('V2_VIEW_MISMATCH')
  _v2_view_record(lock,path,graph[path],allow_bundled=True)

def v2_alias_bindings(lock):
 """Complete unchanged-alias identity/edge join; raw lock remains untouched."""
 _v2_consistent_graph(lock);graph=lock['packages'];aliases={}
 for path,row in graph.items():
  if not path:continue
  install=path.rsplit('/node_modules/',1)[-1].removeprefix('node_modules/')
  if row.get('name',install)!=install:
   aliases[path]={'recordDigest':_digest(row),'legacyRecordDigest':_digest(_v2_view_record(lock,path,row,allow_bundled=True)),'canonical':row['name'],'incoming':[]}
 for owner,row in graph.items():
  for section in ('dependencies','devDependencies','optionalDependencies','peerDependencies'):
   edges=row.get(section,{})
   if not isinstance(edges,dict):_fail('V2_ALIAS_EDGES')
   for name,spec in edges.items():
    destination=_resolve(graph,owner,name,peer=section=='peerDependencies')
    if destination not in aliases:continue
    canonical=aliases[destination]['canonical'];prefix='npm:'+canonical+'@'
    if not isinstance(spec,str) or not spec.startswith(prefix):_fail('V2_ALIAS_IDENTITY')
    try:valid=NpmSpec(normalize_npm_range(spec[len(prefix):])).match(Version(graph[destination]['version']))
    except (ValueError,TypeError,KeyError):_fail('V2_ALIAS_RANGE')
    if not valid:_fail('V2_ALIAS_RANGE')
    aliases[destination]['incoming'].append((owner,section,name,spec,destination))
 for row in aliases.values():
  if not row['incoming']:_fail('V2_ALIAS_ORPHAN')
  row['incoming'].sort()
 return aliases


def _index_omission_edges(graph, locations):
 incoming={location:[] for location in locations}
 for owner,parent in graph.items():
  for section in ('dependencies','devDependencies','optionalDependencies','peerDependencies'):
   declarations=parent.get(section,{})
   if not isinstance(declarations,dict):_fail('EDGE_UNPROVEN')
   for name,spec in declarations.items():
    if section=='dependencies' and name in parent.get('optionalDependencies',{}):continue
    location=_resolve(graph,owner,name,section=='peerDependencies')
    if location in incoming:
     incoming[location].append((owner,parent,section,name,spec))
 return incoming

def verify_platform_absence(lock,rules):
 validate_rules_shape(rules)
 version=lock.get('lockfileVersion')
 if (type(version) is not int or version not in (2,3) or rules['kind']!='NPM_V'+str(version)+'_SRI_PLATFORM_ABSENCE_V1'
   or version==3 and 'dependencies' in lock or version==2 and not isinstance(lock.get('dependencies'),dict)):_fail('LOCK_UNSUPPORTED')
 if version==2:_v2_consistent_graph(lock)
 host=observe_node_host()
 if host!=rules['host']:_fail('HOST_CHANGED')
 graph=lock.get('packages');proof={};total=0
 if (not isinstance(graph,dict) or '' not in graph or len(graph)>10001
   or any(not isinstance(v,dict) for v in graph.values())):_fail('GRAPH_UNPROVEN')
 incoming_by_location=None
 for evidence in rules['artifacts']:
  location=evidence['instance'];row=graph.get(location)
  if (not isinstance(row,dict) or row.get('optional') is not True
    or 'devOptional' in row and row['devOptional'] is not False):_fail('OPTIONAL_UNPROVEN')
  install_name=location.rsplit('/node_modules/',1)[-1].removeprefix('node_modules/');canonical=row.get('name',install_name)
  from urllib.parse import urlsplit
  resolved=row.get('resolved')
  if not isinstance(resolved,str):_fail('RESOLVED_UNPROVEN')
  url=urlsplit(resolved)
  if url.scheme!='https' or not url.hostname or url.username or url.password or url.query or url.fragment:_fail('RESOLVED_UNPROVEN')
  if version==2:_v2_view_record(lock,location,row)
  manifest,artifact,size=_archive(evidence['archivePath'],row,canonical);total+=size
  if total>total_archive_budget(rules):_fail('TOTAL_ARCHIVE_LIMIT')
  os_ok=_selectors(manifest.get('os'),host['platform']);cpu_ok=_selectors(manifest.get('cpu'),host['arch'])
  _selectors(manifest.get('libc'),'windows-libc-not-applicable')
  if os_ok and cpu_ok:_fail('HOST_APPLICABLE')
  # libc is not applicable on supported Windows hosts. A Unix host is not
  # admitted by the explicit host schema; no guessed libc evaluation occurs.
  if incoming_by_location is None:
   incoming_by_location=_index_omission_edges(graph,{item['instance'] for item in rules['artifacts']})
  incoming=[]
  for owner,parent,section,name,spec in incoming_by_location[location]:
   if section!='optionalDependencies' or not isinstance(spec,str):_fail('REQUIRED_INCOMING_EDGE')
   requirement=spec
   if spec.startswith('npm:'):
    prefix='npm:'+canonical+'@'
    if not spec.startswith(prefix):_fail('ALIAS_UNPROVEN')
    requirement=spec[len(prefix):]
   elif name!=canonical:_fail('EDGE_IDENTITY')
   try:valid=NpmSpec(normalize_npm_range(requirement)).match(Version(row['version']))
   except (ValueError,KeyError,TypeError) as exc:raise NpmPlatformEvidenceError('NPM_PLATFORM_EDGE_RANGE_UNPROVEN') from exc
   if not valid:_fail('EDGE_RANGE_MISMATCH')
   if version==2 and owner:_v2_view_record(lock,owner,parent)
   incoming.append({'owner':owner,'section':section,'name':name,'specifier':spec,'target':location})
  if not incoming:_fail('ORPHAN_OMISSION')
  proof[location]={'path':location,'installName':install_name,'canonicalName':canonical,'version':row['version'],
    'resolved':resolved,'outcome':'VERIFIED_PLATFORM_INAPPLICABLE','host':host,
    'platformMetadata':{k:manifest[k] for k in ('os','cpu','libc') if k in manifest},
    'lockRecordDigest':_digest(row),'incoming':sorted(incoming,key=lambda r:(r['owner'],r['section'],r['name'])),**artifact}
 return proof
