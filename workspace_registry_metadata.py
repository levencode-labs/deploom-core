"""Deadline-aware, request-local workspace metadata windows."""
from concurrent.futures import ThreadPoolExecutor, as_completed

from registry_request_context import request_context


def fetch_workspace_packuments(client, names):
    """Parallelize only independent public reads; never publish late cache writes.

    All selected names must have passed local slot/route validation first. Private
    sessions stay sequential. A stateful response discards speculative results
    and lets the original session establish its ordered state. Workers reuse
    their connections across successful windows. They have no shared or durable
    cache and no progress callback. Timed-out work cannot publish into the caller
    after return. The HTTP supervisor owns its deadline.
    """
    from dependency_live_roadmap_generator import (
        DraftBudgetExceeded, RegistryInfrastructureError, _registry_prefetch_client,
    )
    names = tuple(dict.fromkeys(names))
    context = request_context(client.session, client.registry, client.metadata_cache_tool_version)
    deadline = client.deadline
    if len(names) < 2 or context[0] is None or not context[1] or deadline is None:
        return {name: client.fetch_npm_metadata(name) for name in names}

    workers = []
    last = {}
    results = {}
    width = min(4, len(names))
    pool = ThreadPoolExecutor(max_workers=width)
    try:
        deadline.check('workspace-metadata')
        for _ in range(width):
            worker = _registry_prefetch_client(client)
            workers.append(worker)
            worker.metadata_cache_dir = None
            worker.metadata_cache_ttl = 0
            worker.progress = lambda **kwargs: None

        for offset in range(0, len(names), width):
            deadline.check('workspace-metadata')
            stateful = False
            errors = {}
            futures = {}
            for index, name in enumerate(names[offset:offset + width]):
                future = pool.submit(workers[index]._fetch_npm_metadata_result, name)
                futures[future] = name
                last[index] = future
            for future in as_completed(futures, timeout=max(0, deadline.remaining)):
                name = futures[future]
                try:
                    metadata, reusable = future.result()
                    results[name] = metadata
                    stateful |= not reusable
                except RegistryInfrastructureError as exc:
                    errors[name] = exc
            deadline.check('workspace-metadata')
            if stateful or request_context(client.session, client.registry, client.metadata_cache_tool_version) != context:
                break
            if errors:
                raise errors[sorted(errors)[0]]
        else:
            return {name: results[name] for name in names}
    except TimeoutError:
        raise DraftBudgetExceeded('workspace-metadata') from None
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
        for index, worker in enumerate(workers):
            future = last.get(index)
            if future is None:
                worker.session.close()
            else:
                # On timeout the last request can still own this session.
                future.add_done_callback(lambda _, session=worker.session: session.close())
    return {name: client.fetch_npm_metadata(name) for name in names}
