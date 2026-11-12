"""Fresh checks of the actual caller-authorized npm workspace.

This owner does not issue permissions or publish checkpoints. Unlike the private
candidate verifier it never substitutes a prepared copy for the supplied working
workspace. The caller must explicitly authorize npm-ci and the pinned commands.
Only supported physical manifest/edge boundaries are observed, not package
payload/.bin integrity, arbitrary JS semantics or external input closure.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
import shutil
import time
import re
import uuid

from source_snapshot import (verification_source_snapshot_scope,
    validate_source_snapshot, source_snapshot_live_source_continuity)
from resolved_dependency_state import (capture_resolved_dependency_state,
    observe_npm_dependency_obligations,npm_root_assignment_from_obligations)
from verification_process_supervisor import has_guaranteed_tree_backend, run_supervised
from verification_stage_checkpoint import pinned_inline_node_invocation
from verification_proof import environment_snapshot_fingerprint


class MaterializedWorkspaceVerificationError(RuntimeError):
    """Unproven current state; never a learned solver incompatibility."""


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
        ensure_ascii=False).encode()).hexdigest()


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _sha_file(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def verify_current_workspace(project_dir, *, expected_source_key, dependency_plan,
        commands, cache_dir, deadline, final_profile_digest, environment=None, materialize=False,
        environment_contract='LEGACY_INHERITED_ENV_V1', trusted_pre_popen_guard=None, command_cache_directories=None,
        generated_output_spec=None, workspace_registry=None):
    """Freshly check THIS authorized workspace; optional cold-only npm-ci.

    No caller-provided evidence, reusable command PASS or previous prepared tree
    is accepted. Commands and installation permission belong to the host caller.
    A crash before the returned observation is durably closed requires fresh
    verification of the same attempt, never a manufactured resumed PASS.
    """
    from baseline_constraint_verifier import (project_check_command_argv,
        observed_resolved_assignment, observed_resolved_hash)
    operation_started=time.monotonic()
    operations=[];failed_command_diagnostic=None
    def fail(code):
        error=MaterializedWorkspaceVerificationError(code)
        error.operation_observations=tuple(operations)
        if failed_command_diagnostic is not None:error._private_failed_command_diagnostic=failed_command_diagnostic
        raise error
    def remaining():
        value=deadline-time.time()
        if value <= 0: fail('CURRENT_WORKSPACE_DEADLINE_EXCEEDED')
        return max(1, int(value))
    if (isinstance(deadline,bool) or not isinstance(deadline,(int,float))
            or not math.isfinite(deadline)):
        fail('CURRENT_WORKSPACE_INVALID_DEADLINE')
    remaining()
    if not isinstance(final_profile_digest,str) or re.fullmatch('[0-9a-f]{64}',final_profile_digest) is None:
        fail('CURRENT_WORKSPACE_FINAL_PROFILE_UNPROVEN')
    invocation_id=uuid.uuid4().hex
    if type(materialize) is not bool:fail('CURRENT_WORKSPACE_INSTALL_POLICY_UNPROVEN')
    if (not isinstance(dependency_plan,dict)
            or type(dependency_plan.get('schemaVersion')) is not int
            or dependency_plan.get('schemaVersion') != 1
            or dependency_plan.get('obligationPlanDigest') != _digest({k:v for k,v in dependency_plan.items() if k!='obligationPlanDigest'})):
        fail('CURRENT_WORKSPACE_PLAN_UNPROVEN')
    if (not isinstance(commands,(tuple,list)) or not 1<=len(commands)<=64
            or any(not isinstance(c,str) or not c.strip() or len(c)>4096 for c in commands)):
        fail('CURRENT_WORKSPACE_PROFILE_UNPROVEN')
    if not has_guaranteed_tree_backend():
        fail('CURRENT_WORKSPACE_PROCESS_CLOSURE_UNAVAILABLE')
    from workspace_npm_obligations import WORKSPACE_OBLIGATION_KIND, guard_workspace_install_inputs, guard_workspace_npmrc
    from workspace_npm_preflight import WORKSPACE_NPM_POLICY, isolated_workspace_npm_environment
    workspace_mode = dependency_plan.get("kind") == WORKSPACE_OBLIGATION_KIND
    project=Path(project_dir).absolute();cache=Path(cache_dir).absolute()
    if workspace_mode and (project != project.resolve() or project.is_relative_to(cache.resolve())):
        fail('CURRENT_WORKSPACE_PATH_UNPROVEN')
    if (project.is_symlink() or cache.is_symlink()
            or (hasattr(project,'is_junction') and project.is_junction())
            or (hasattr(cache,'is_junction') and cache.is_junction())
            or not project.is_dir() or not cache.is_dir()
            or cache.resolve().is_relative_to(project.resolve())):
        fail('CURRENT_WORKSPACE_PATH_UNPROVEN')
    project=project.resolve();cache=cache.resolve()
    modules=project/'node_modules'
    if modules.is_symlink() or (hasattr(modules,'is_junction') and modules.is_junction()):
        fail('CURRENT_WORKSPACE_DEPENDENCY_ROOT_REPARSE_UNPROVEN')
    if materialize and modules.exists() and (not modules.is_dir() or any(modules.iterdir())):
        fail('CURRENT_WORKSPACE_EXISTING_TREE_REQUIRES_RECOVERABLE_STAGING')
    from project_execution_environment import (workspace_execution_environment,
        project_environment_fingerprint,project_environment_observation)
    if environment_contract=='HOST_OWNED_PROJECT_EXECUTION_ENV_V1' and (os.name!='nt' or str(project).startswith('\\\\')):
        fail('CURRENT_WORKSPACE_ENVIRONMENT_BOUNDARY_UNSUPPORTED')
    env=workspace_execution_environment(os.environ if environment is None else environment,cache,
        contract=environment_contract)
    from project_execution_environment import command_cache_environments
    command_envs=command_cache_environments(env,command_cache_directories,len(commands),
        contract=environment_contract,guarded=trusted_pre_popen_guard is not None)
    if any(str(env.get(k,'')).strip() for k in ('NODE_OPTIONS','NODE_PATH')):
        fail('CURRENT_WORKSPACE_EXTERNAL_NODE_LOADER_UNPROVEN')
    from draft_npm_preflight import _npm_command
    try:
        node,npm_entry=_npm_command(path=env.get('PATH'));npm=Path(npm_entry)
    except OSError:
        fail('CURRENT_WORKSPACE_TOOLCHAIN_UNAVAILABLE')
    tools={'nodeSha256':_sha_file(node),'npmCliSha256':_sha_file(npm)}
    lock_path = project / "package-lock.json"
    if workspace_mode:
        info = lock_path.lstat()
        if lock_path.is_symlink() or getattr(info, "st_file_attributes", 0) & 0x400:
            fail('CURRENT_WORKSPACE_APPROVED_LOCK_MISMATCH')
        if tools != dependency_plan.get("resolverToolchain"):
            fail('CURRENT_WORKSPACE_RESOLVER_TOOLCHAIN_MISMATCH')
        if materialize and (not isinstance(workspace_registry, str)
                or _sha(workspace_registry.encode()) != dependency_plan.get("registrySha256")):
            fail('CURRENT_WORKSPACE_RESOLVER_REGISTRY_MISMATCH')
    lock=lock_path.read_bytes()
    if _sha(lock)!=dependency_plan['approvedLockSha256']:fail('CURRENT_WORKSPACE_APPROVED_LOCK_MISMATCH')

    def run(argv,label,command_index=None, execution_env=None):
        nonlocal failed_command_diagnostic
        failed_command_diagnostic=None
        started=time.monotonic()
        actual_env = execution_env if execution_env is not None else command_envs.get(command_index,env)
        launch_options={}
        if environment_contract=='HOST_OWNED_PROJECT_EXECUTION_ENV_V1':
            launch_options['expected_project_environment_digest']=project_environment_fingerprint(actual_env,contract=environment_contract)
        if trusted_pre_popen_guard is not None:
            launch_options.update(trusted_pre_popen_guard=trusted_pre_popen_guard,
                trusted_pre_popen_context={'invocationId':invocation_id,'operation':'strict-frozen-install' if command_index is None else 'project-command',
                    'commandIndex':command_index,'sealedCommandHash':None if command_index is None else _sha(commands[command_index-1].encode()),
                    'profileDigest':final_profile_digest,'argvDigest':_digest(argv)})
        x=run_supervised(argv,project,timeout_seconds=remaining(),base_env=actual_env,
            progress_label=label,max_output_bytes=65536,require_guaranteed_tree=True,**launch_options)
        if command_index is not None and x.returncode!=0:
            failed_command_diagnostic={'commandIndex':command_index,'returnCode':x.returncode,
                'invocationId':invocation_id,'stdoutTail':(x.stdout or '').encode('utf-8')[-8192:].decode('utf-8',errors='ignore')}
        s=getattr(x,'supervision',None)
        operations.append({'operation':'strict-frozen-install' if command_index is None else 'project-command',
            'commandIndex':command_index,'argvDigest':_digest(argv),'elapsedStartMs':int((started-operation_started)*1000),
            'durationMs':int((time.monotonic()-started)*1000),'returnCode':x.returncode,
            'supervision':getattr(s,'quality',None),'descendantsRemaining':getattr(s,'descendants_remaining',None),
            'timedOut':bool(getattr(x,'timed_out',False)),'cancelled':bool(getattr(x,'cancelled',False))})
        if 'expected_project_environment_digest' in launch_options:
            from project_execution_environment import native_launch_observation_matches
            launch=getattr(x,'project_execution_environment',None)
            if not native_launch_observation_matches(launch,launch_options['expected_project_environment_digest'],_digest(str(project))):
                fail('CURRENT_WORKSPACE_ACTUAL_ENVIRONMENT_UNPROVEN')
            operations[-1]['projectExecutionEnvironment']=dict(launch)
        witness=getattr(x,'guarded_spawn_witness',None)
        if witness is not None:operations[-1]['guardedSpawnWitness']=dict(witness)
        remaining()
        if (getattr(s,'quality',None)!='guaranteed-tree'
                or getattr(s,'descendants_remaining',None)!=0
                or getattr(x,'timed_out',False) or getattr(x,'cancelled',False)):
            fail('CURRENT_WORKSPACE_PROCESS_CLOSURE_UNPROVEN')
        return x
    with verification_source_snapshot_scope(
        project, timeout_seconds=remaining(), strict_cleanup=True, observe_live_source=True
    ) as snapshot:
        if snapshot.key!=expected_source_key:fail('CURRENT_WORKSPACE_SOURCE_MISMATCH')
        from standalone_build_outputs import (PROFILE, validate_spec, require_absent, capture_receipt, receipt_current)
        typed_output = bool(snapshot.input_policy and snapshot.input_policy.generated_output_profile)
        if typed_output != (generated_output_spec is not None):fail('CURRENT_WORKSPACE_OUTPUT_CONTRACT_REQUIRED')
        output_receipt=None
        if typed_output:
            if snapshot.input_policy.generated_output_profile!=PROFILE:fail('CURRENT_WORKSPACE_OUTPUT_PROFILE_UNSUPPORTED')
            validate_spec(generated_output_spec,project,commands)
            require_absent(project,deadline=deadline)
        output_binding=None
        if typed_output:
            output_binding={'sourceSnapshotKey':snapshot.key,'profileDigest':final_profile_digest,'invocationId':invocation_id,
                'dependencyPlanDigest':dependency_plan['obligationPlanDigest'],'approvedLockSha256':dependency_plan['approvedLockSha256'],
                'environmentDigest':project_environment_fingerprint(env,contract=environment_contract),
                'toolchain':tools,'buildCommandDigest':_sha(commands[0].encode())}
        def source_guard():
            if workspace_mode and "rootNpmrcSha256" in dependency_plan:
                guard_workspace_npmrc(project, dependency_plan)
            remaining();validate_source_snapshot(snapshot,timeout_seconds=remaining())
            if (not source_snapshot_live_source_continuity(snapshot,timeout_seconds=remaining())
                    or (project/'package-lock.json').read_bytes()!=lock
                    or tools!={'nodeSha256':_sha_file(node),'npmCliSha256':_sha_file(npm)}):
                fail('CURRENT_WORKSPACE_INPUT_CHANGED')
        source_guard()
        installation={'status':'EXISTING_TREE_REQUIRES_PHYSICAL_OBSERVATION','scriptsEnabled':False}
        if materialize:
            if workspace_mode:
                guard_workspace_install_inputs(project, dependency_plan, lock)
                configs = [project / f".deploom-ci-{invocation_id}-{name}.npmrc" for name in ("user", "global")]
                if any(path.exists() or path.is_symlink() for path in configs):
                    fail('CURRENT_WORKSPACE_INSTALL_CONFIG_UNPROVEN')
                install_argv = [node, str(npm), "ci", *WORKSPACE_NPM_POLICY,
                                "--registry", workspace_registry, "--cache", str(cache),
                                "--userconfig", str(configs[0]), "--globalconfig", str(configs[1])]
                install_env = isolated_workspace_npm_environment(env)
            else:
                install_argv = [node,str(npm),'ci','--offline','--ignore-scripts','--strict-peer-deps',
                                '--engine-strict','--force=false','--legacy-peer-deps=false','--no-audit','--no-fund',
                                '--cache',str(cache)]
                install_env = None
            install=run(install_argv,'current-workspace frozen install',execution_env=install_env)
            source_guard()
            if install.returncode!=0:fail('CURRENT_WORKSPACE_INSTALL_NOT_VERIFIED')
            installation={'status':'FRESH_COLD_FROZEN_INSTALL_OBSERVED','scriptsEnabled':False,
                'supervision':'guaranteed-tree','stdoutDigest':_sha((install.stdout or '').encode())}
        if typed_output:require_absent(project,deadline=deadline)
        resolver_key = _digest({'sourceKey':snapshot.key,'plan':dependency_plan['obligationPlanDigest'],
                                'toolchain':tools,'environment':environment_snapshot_fingerprint(env)})
        def resolved_state(observed_hash):
            return capture_resolved_dependency_state(
                project, manager='npm', resolver_input_key=resolver_key,
                observed_resolved_hash=observed_hash, proof_cache_dir=None)

        state = None
        if not workspace_mode:
            roots = npm_root_assignment_from_obligations(dependency_plan)
            state = resolved_state(observed_resolved_hash(observed_resolved_assignment(project, roots)))
        origin={'schemaVersion':1,'scope':'CURRENT_HOST_WORKSPACE',
            'inputSourceSnapshotKey':snapshot.key,'workspacePathDigest':_digest(str(project)),
            'resolvedLockfileHash':_sha(lock),'toolchain':tools}
        if workspace_mode:
            origin["workspaceVerificationBinding"] = _digest({
                "source": snapshot.key, "obligationPlan": dependency_plan["obligationPlanDigest"],
                "resolver": dependency_plan["resolverIdentitySha256"], "profile": final_profile_digest,
                "commands": [_sha(command.encode()) for command in commands], "materialize": materialize,
                "executionEnvironment": project_environment_fingerprint(env, contract=environment_contract),
            })
        auxiliary_observations=[]
        def tree(phase):
            def auxiliary(rows):
                auxiliary_observations.append({'phase':phase,'directories':rows,'arbitraryFilesystemSemanticsVerified':False})
            try:
                return observe_npm_dependency_obligations(project,dependency_plan,
                    source_origin_digest=_digest(origin),
                    resolved_state_key=state.key if state is not None else dependency_plan["obligationPlanDigest"],
                    deadline=time.monotonic()+max(0,deadline-time.time()),auxiliary_directory_observer=auxiliary)
            except Exception as exc:
                exc.operation_observations=tuple(operations)
                raise
        initial=tree('initial');rows=[]
        if workspace_mode:
            # The initial observation is internal until the observed tree binds the resolved state.
            state = resolved_state(initial["materializedTreeObservationDigest"])
            if state.lockfile_hash != origin["resolvedLockfileHash"]:
                fail('CURRENT_WORKSPACE_INPUT_CHANGED')
            initial["resolvedStateKey"] = state.key
        if not materialize:installation['status']='EXISTING_TREE_PHYSICALLY_OBSERVED'
        for index,command in enumerate(commands,1):
            if typed_output:
                if index==1:require_absent(project,deadline=deadline)
                elif not receipt_current(project,generated_output_spec,output_receipt,deadline=deadline,binding=output_binding):
                    fail('CURRENT_WORKSPACE_OUTPUT_CHANGED')
            source_guard();before=tree('before-command-'+str(index))
            if before!=initial:fail('CURRENT_WORKSPACE_TREE_CHANGED')
            inline=pinned_inline_node_invocation(command,env)
            argv=inline['argv'] if inline else project_check_command_argv(command,env)
            result=run(argv,'current-workspace project check',index)
            source_guard();after=tree('after-command-'+str(index))
            if after!=initial:fail('CURRENT_WORKSPACE_TREE_CHANGED')
            if result.returncode!=0:fail('CURRENT_WORKSPACE_COMMAND_FAILED')
            if typed_output:
                if index==1:output_receipt=capture_receipt(project,generated_output_spec,deadline=deadline,binding=output_binding)
                elif not receipt_current(project,generated_output_spec,output_receipt,deadline=deadline,binding=output_binding):
                    fail('CURRENT_WORKSPACE_OUTPUT_CHANGED')
            rows.append({'commandIndex':index,'commandDigest':_sha(command.encode()),
                'freshCommandInvocationId':invocation_id,'finalVerificationProfileDigest':final_profile_digest,
                'commandBoundaryGuard':'PRE_POST_OBSERVED',
                'status':'PASS','origin':'EXECUTED_FRESH','returnCode':0,'supervision':'guaranteed-tree',
                'sourceSnapshotKey':snapshot.key,'resolvedStateKey':state.key,
                'obligationPlanDigest':dependency_plan['obligationPlanDigest'],
                'materializedTreeObservationDigest':initial['materializedTreeObservationDigest'],
                'inlineExecution':inline,'stdoutDigest':_sha((result.stdout or '').encode())})
        source_guard();final=tree('final')
        if final!=initial:fail('CURRENT_WORKSPACE_TREE_CHANGED')
        result={'schemaVersion':1,'status':'CURRENT_WORKSPACE_PROFILE_OBSERVED',
            'authority':'NON_REUSABLE_CORE_CURRENT_WORKSPACE_OBSERVATION',
            'executionScope':'REGISTERED_CURRENT_WORKSPACE','freshCommandInvocationId':invocation_id,
            'finalVerificationProfileDigest':final_profile_digest,
            'deliveredSourceObservationDigest':_digest(origin),
            'liveMaterializedTreeObservationDigest':final['materializedTreeObservationDigest'],
            'finalBoundaryObserved':True,
            'sourceSnapshotKey':snapshot.key,'workspacePathDigest':_digest(str(project)),
            'resolvedStateKey':state.key,'resolvedLockfileHash':state.lockfile_hash,
            'materializedSourceOrigin':origin,'materializedDependencyObligations':final,
            'environmentDigest':project_environment_fingerprint(env,contract=environment_contract),'commandObservations':rows,
            'installation':installation,
            'currentWorkspaceVerified':False,'checkpointPublished':False,'fullAcceptance':False}
    remaining()
    if typed_output:
        if not receipt_current(project,generated_output_spec,output_receipt,deadline=deadline,binding=output_binding):
            fail('CURRENT_WORKSPACE_OUTPUT_CHANGED')
        result['generatedOutputObservation']=output_receipt
    result['sourceSnapshotCleanupClosed']=True
    execution_environment=project_environment_observation(env,contract=environment_contract)
    if execution_environment is not None:result['projectExecutionEnvironment']=execution_environment
    result['ownedCleanupConfirmed']=True
    result['auxiliaryDirectoryObservations']=auxiliary_observations
    result['arbitraryFilesystemSemanticsVerified']=False
    if command_envs:result['commandEnvironmentDigests']={str(i):project_environment_fingerprint(e,contract=environment_contract) for i,e in command_envs.items()}
    result['ownerOperationObservations']=operations
    result['ownerElapsedMs']=int((time.monotonic()-operation_started)*1000)
    return result
