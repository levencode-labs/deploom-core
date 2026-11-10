"""Deadline-aware, request-local workspace metadata windows."""
from concurrent.futures import ThreadPoolExecutor, as_completed

from registry_request_context import request_context


def fetch_workspace_packuments(client, names):
    """Parallelize only independent public reads; never publish late cache writes.

    All selected names must have passed local slot/route validation first. Private
    sessions stay sequential. A stateful response discards speculative results
    and lets the original session establish its ordered state. Workers have no
    shared or durable cache and no progress callback; timed-out work cannot
    publish into the caller after return. The HTTP supervisor owns its deadline.
    """
    from dependency_live_roadmap_generator import (
        DraftBudgetExceeded, RegistryInfrastructureError, _registry_prefetch_client,
    )
    names = tuple(dict.fromkeys(names))
    context = request_context(client.session, client.registry, client.metadata_cache_tool_version)
    deadline = client.deadline
    if len(names) < 2 or context[0] is None or not context[1] or deadline is None:
        return {name: client.fetch_npm_metadata(name) for name in names}

    def fetch(name):
        worker = _registry_prefetch_client(client)
        worker.metadata_cache_dir = None
        worker.metadata_cache_ttl = 0
        worker.progress = lambda **kwargs: None
        try:
            return worker._fetch_npm_metadata_result(name)
        finally:
            worker.session.close()

    results = {}
    # Never enqueue an unbounded tail behind four workers.
    for offset in range(0, len(names), 4):
        deadline.check('workspace-metadata')
        window = names[offset:offset + 4]
        pool = ThreadPoolExecutor(max_workers=len(window))
        stateful = False
        errors = {}
        try:
            futures = {pool.submit(fetch, name): name for name in window}
            for future in as_completed(futures, timeout=max(0, deadline.remaining)):
                name = futures[future]
                try:
                    metadata, reusable = future.result()
                    results[name] = metadata
                    stateful |= not reusable
                except RegistryInfrastructureError as exc:
                    errors[name] = exc
        except TimeoutError:
            raise DraftBudgetExceeded('workspace-metadata') from None
        finally:
            pool.shutdown(wait=False, cancel_futures=True)
        deadline.check('workspace-metadata')
        if stateful or request_context(client.session, client.registry, client.metadata_cache_tool_version) != context:
            return {name: client.fetch_npm_metadata(name) for name in names}
        if errors:
            raise errors[sorted(errors)[0]]
    return {name: results[name] for name in names}
