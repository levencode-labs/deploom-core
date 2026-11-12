"""Bound the npm lock delta to declared targets and authorized placement repair."""
from __future__ import annotations

from collections import defaultdict, deque

from resolution_inventory import npm_lock_resolved_instance

INSTALL_SECTIONS = ("dependencies", "devDependencies", "optionalDependencies")


def peer_context(consumer: str) -> str:
    parent, separator, _ = ("/" + consumer).rpartition("/node_modules/")
    return parent.strip("/") if separator else consumer


def _edges(packages: dict, consumer: str) -> dict:
    entry = packages.get(consumer, {})
    edges = {}
    for section in (*INSTALL_SECTIONS, "peerDependencies"):
        for name, spec in entry.get(section, {}).items():
            # Match Arborist and the preflight peer check when an installed edge shadows a peer.
            if section == "peerDependencies" and any(
                name in entry.get(installed, {}) for installed in ("dependencies", "optionalDependencies")
            ):
                continue
            context = peer_context(consumer) if section == "peerDependencies" else consumer
            provider = npm_lock_resolved_instance(packages, name, context)
            edges[section, name] = (spec, provider)
    return edges


def _held_root_peer_bindings(packages, root_targets, *, reauthored=None):
    if not root_targets:
        return
    root = packages[""]
    authorized = set(root_targets)
    if reauthored is not None and reauthored[0] == ".":
        authorized.add(reauthored[2])
    held_names = {name for section in INSTALL_SECTIONS for name in root.get(section, {})} - authorized
    for consumer in sorted(held_names):
        path = f"node_modules/{consumer}"
        row = packages.get(path, {})
        if row.get("link") or not row.get("version"):
            continue
        peers = row.get("peerDependencies", {})
        for name in sorted(peers.keys() & root_targets.keys()):
            if name in row.get("dependencies", {}) or name in row.get("optionalDependencies", {}):
                continue
            provider = npm_lock_resolved_instance(packages, name, "")
            if provider is not None:
                yield {"path": path, "dependency": name, "section": "peerDependencies",
                       "beforeVersion": provider[1]}


def forced_root_peer_conflicts(packages, root_targets, *, reauthored=None):
    """An unchanged direct root consumer and a direct root peer have fixed slots."""
    return [{**row, "requestedVersion": root_targets[row["dependency"]]}
            for row in _held_root_peer_bindings(packages, root_targets, reauthored=reauthored)
            if row["beforeVersion"] != root_targets[row["dependency"]]]


def forced_root_peer_domain_conflicts(packages, root_domains):
    """Identify held peers whose baseline version is absent from a known domain.

    An empty domain here represents scope with candidate selection still
    pending. Its declaration remains authorized, so it is not a held consumer.
    """
    conflicts = []
    for row in _held_root_peer_bindings(packages, root_domains):
        versions = root_domains[row["dependency"]]
        if versions and row["beforeVersion"] not in versions:
            conflicts.append({**row, "requestedVersion": versions[0], "requestedVersions": list(versions)})
    return conflicts


def _instance(packages, declaration):
    owner, _, name = declaration
    return npm_lock_resolved_instance(packages, name, "" if owner == "." else owner)


def _artifact(entry):
    return tuple(entry.get(key) for key in ("version", "resolved", "integrity", "link"))


def _relocation_identity(path, entry):
    if "node_modules" not in path.split("/") or entry.get("link"):
        return None
    version, resolved, integrity, _ = _artifact(entry)
    if not all(isinstance(value, str) and value for value in (version, resolved, integrity)):
        return None
    if not resolved.startswith("https://"):
        return None
    name = ("/" + path).rsplit("/node_modules/", 1)[-1]
    return (name, version, resolved, integrity)


def _equivalent_relocations(before, after, before_edges, after_edges):
    """Match only unique unchanged artifacts with unchanged incident edges."""
    if not (before.keys() - after.keys() and after.keys() - before.keys()):
        return {}
    indexes = []
    for graph in (before, after):
        locations = defaultdict(list)
        for path, entry in graph.items():
            identity = _relocation_identity(path, entry)
            if identity is not None:
                locations[identity].append(path)
        indexes.append(locations)
    old, new = indexes
    moves = {}
    for identity, old_paths in old.items():
        new_paths = new.get(identity, ())
        if len(old_paths) == len(new_paths) == 1:
            left, right = old_paths[0], new_paths[0]
            if left not in after and right not in before and before[left] == after[right]:
                moves[right] = left
    if not moves:
        return {}

    inverse = {left: right for right, left in moves.items()}
    for left in before.keys() | (after.keys() - moves.keys()):
        right = inverse.get(left, left)
        prior, next_edges = before_edges.get(left, {}), after_edges.get(right, {})
        moved_consumer = left != right
        if moved_consumer and any(provider is None for _, provider in prior.values()):
            return {}
        for key in prior.keys() | next_edges.keys():
            old_spec, old_provider = prior.get(key, (None, None))
            new_spec, new_provider = next_edges.get(key, (None, None))
            touches_move = (old_provider and old_provider[0] in inverse
                            or new_provider and new_provider[0] in moves)
            if moved_consumer or touches_move:
                if new_provider is not None:
                    new_provider = (moves.get(new_provider[0], new_provider[0]), new_provider[1])
                if (old_spec, old_provider) != (new_spec, new_provider):
                    return {}
    return moves


def _displaced_held_slots(before, after, held_pairs, replaced_slots):
    """Identify a unique held copy displaced by an explicitly selected version."""
    candidates = {(old, new) for old, new in held_pairs
                  if old in replaced_slots and new not in before and before[old] == after[new]}
    if not candidates:
        return {}
    counts = []
    for graph in (before, after):
        identities = defaultdict(int)
        for path, entry in graph.items():
            identity = _relocation_identity(path, entry)
            if identity is not None:
                identities[identity] += 1
        counts.append(identities)
    return {new: old for old, new in sorted(candidates)
            if (identity := _relocation_identity(old, before[old])) is not None
            and _relocation_identity(new, after[new]) == identity
            and all(index[identity] == 1 for index in counts)}


def _check_held_graph(before, after, before_edges, after_edges, owners, authorized, moves):
    """Preserve held closure and report independent conflicts in one pass."""
    new_path = {old: new for new, old in moves.items()}
    pending = deque(sorted(owners))
    visited = set(owners)
    conflicts = []
    conflict_count = 0
    while pending:
        consumer = pending.popleft()
        left = before_edges[consumer]
        right = after_edges[new_path.get(consumer, consumer)]
        for section, name in sorted(left.keys() | right.keys()):
            if consumer in owners and (consumer or ".", section, name) in authorized:
                continue
            old_spec, old_provider = left.get((section, name), (None, None))
            new_spec, new_provider = right.get((section, name), (None, None))
            normalized = (moves.get(new_provider[0], new_provider[0]), new_provider[1]) if new_provider else None
            old_entry = before[old_provider[0]] if old_provider else None
            failure = None
            if (old_spec, old_provider) != (new_spec, normalized):
                failure = "HELD_LOCK_PROVIDER_CHANGED"
            elif old_entry is not None and _artifact(old_entry) != _artifact(after[new_provider[0]]):
                failure = "HELD_LOCK_TRANSITIVE_ARTIFACT_CHANGED"
            if failure is not None:
                conflict_count += 1
                if len(conflicts) < 8:
                    conflicts.append({"status": "RESOLUTION_FAILED", "code": failure,
                                      "path": consumer, "dependency": name, "section": section})
                continue
            if old_entry is None:
                continue
            if old_entry.get("link"):
                target = old_entry["resolved"].replace("\\", "/").strip("/")
            else:
                target = old_provider[0]
            if target not in visited:
                visited.add(target)
                pending.append(target)
    if conflict_count > 1:
        return {**conflicts[0], "heldConflictCount": conflict_count, "heldConflicts": conflicts}
    return conflicts[0] if conflicts else None


def _runtime_reachable(edges, owners):
    reached = set(owners)
    pending = deque(owners)
    while pending:
        consumer = pending.popleft()
        for (section, _), (_, provider) in edges[consumer].items():
            if section == "devDependencies" or provider is None:
                continue
            path, _ = provider
            if path not in reached:
                reached.add(path)
                pending.append(path)
    return reached


def _proved_dev_reclassifications(paths, before, after, before_edges, after_edges, owners):
    # npm reclassifies held payloads when their last production consumer changes.
    candidates = []
    for path in paths & before.keys() & after.keys():
        old, new = before[path], after[path]
        old_dev, new_dev = old.get("dev", False), new.get("dev", False)
        if (type(old_dev) is bool and type(new_dev) is bool and old_dev != new_dev
                and {key: value for key, value in old.items() if key != "dev"}
                == {key: value for key, value in new.items() if key != "dev"}):
            candidates.append((path, old_dev, new_dev))
    if not candidates:
        return set()
    runtime_before = _runtime_reachable(before_edges, owners)
    runtime_after = _runtime_reachable(after_edges, owners)
    return {
        path for path, old_dev, new_dev in candidates
        if old_dev == (path not in runtime_before) and new_dev == (path not in runtime_after)
    }


def check_workspace_lock_delta(
    baseline, candidate, manifest_deltas, assignment, changed, reauthored, immutable_instances=frozenset(),
):
    """Reject unrelated node or edge churn using both observed lock graphs.

    A target can affect descendants along changed package rows and provider
    bindings. A retained node with an unchanged binding does not expand scope.
    The closure is conservative and does not prove minimal npm placement.
    """
    if baseline.keys() != candidate.keys() or any(
        baseline[key] != candidate[key] for key in baseline if key != "packages"
    ):
        return {"status": "RESOLUTION_FAILED", "code": "LOCK_ENVELOPE_CHANGED"}
    before, after = baseline["packages"], candidate["packages"]
    if max(len(before), len(after)) > 20000:
        return {"status": "UNKNOWN", "code": "LOCK_DELTA_ENTRY_LIMIT"}

    for path in sorted(immutable_instances):
        original, planned = before.get(path), after.get(path)
        if (original is None or planned is None or _artifact(original) != _artifact(planned)
                or original.get("name") != planned.get("name")):
            return {"status": "RESOLUTION_FAILED", "code": "IMMUTABLE_LOCK_INSTANCE_CHANGED", "path": path}

    owners = {"" if owner == "." else owner for owner, _, _ in assignment} | {""}
    owners.update(path for path in before if "node_modules" not in path.split("/"))
    for owner in sorted(owners):
        expected = dict(before[owner])
        for section, replacements in manifest_deltas.get(owner, {}).items():
            expected[section] = {**expected.get(section, {}), **replacements}
        if after.get(owner) != expected:
            return {"status": "RESOLUTION_FAILED", "code": "LOCK_OWNER_RECORD_CHANGED", "path": owner}
    if {path for path in after if "node_modules" not in path.split("/")} != owners:
        return {"status": "RESOLUTION_FAILED", "code": "LOCK_WORKSPACE_MEMBERSHIP_CHANGED"}

    seeds = set(changed)
    if reauthored is not None:
        seeds.add(reauthored)
    impacted = set()
    held_pairs = set()
    replaced_slots = set()
    for declaration in sorted(assignment):
        left, right = (_instance(graph, declaration) for graph in (before, after))
        if left is None or right is None:
            return {"status": "UNKNOWN", "code": "LOCK_DELTA_INSTANCE_UNAVAILABLE"}
        if declaration not in changed and _artifact(before[left[0]]) != _artifact(after[right[0]]):
            return {"status": "RESOLUTION_FAILED", "code": "HELD_LOCK_ARTIFACT_CHANGED",
                    "declaration": list(declaration)}
        if declaration not in changed:
            held_pairs.add((left[0], right[0]))
        elif left[0] == right[0] and _artifact(before[left[0]]) != _artifact(after[right[0]]):
            replaced_slots.add(left[0])
        if declaration in seeds:
            impacted.update((left[0], right[0]))

    nodes = before.keys() | after.keys()
    before_edges = {path: _edges(before, path) for path in before}
    after_edges = {path: _edges(after, path) for path in after}
    moves = _equivalent_relocations(before, after, before_edges, after_edges)
    displaced = _displaced_held_slots(before, after, held_pairs, replaced_slots)
    relocated = moves.keys() | set(moves.values()) | displaced.keys()
    delta = {path for path in nodes - owners if before.get(path) != after.get(path)}
    for path in sorted(delta):
        if before.get(path, {}).get("link") or after.get(path, {}).get("link"):
            return {"status": "RESOLUTION_FAILED", "code": "LOCK_WORKSPACE_LINK_CHANGED", "path": path}
    queue = deque(sorted(impacted))
    while queue:
        consumer = queue.popleft()
        if consumer in owners:
            continue
        left, right = before_edges.get(consumer, {}), after_edges.get(consumer, {})
        for key in left.keys() | right.keys():
            left_spec, left_provider = left.get(key, (None, None))
            right_spec, right_provider = right.get(key, (None, None))
            left_path = left_provider[0] if left_provider else None
            right_path = right_provider[0] if right_provider else None
            if (_artifact(before.get(consumer, {})) == _artifact(after.get(consumer, {}))
                    and (left_spec, left_path) == (right_spec, right_path)):
                continue
            for provider in (left_provider, right_provider):
                if provider is not None and provider[0] not in impacted:
                    impacted.add(provider[0])
                    queue.append(provider[0])
    outside = delta - impacted - relocated
    if outside:
        outside -= _proved_dev_reclassifications(outside, before, after, before_edges, after_edges, owners)
    held_failure = _check_held_graph(before, after, before_edges, after_edges, owners, seeds, moves | displaced)
    if outside:
        result = {"status": "RESOLUTION_FAILED", "code": "LOCK_UNRELATED_NODE_DELTA",
                  "path": min(outside), "unrelatedCount": len(outside)}
        if held_failure is not None:
            result["heldConflict"] = held_failure
        return result

    if held_failure is not None:
        return held_failure

    edge_changes = 0
    inverse = {old: new for new, old in moves.items()}
    for consumer in sorted(nodes - moves.keys()):
        left = before_edges.get(consumer, {})
        right = {key: (spec, (moves.get(provider[0], provider[0]), provider[1]) if provider else None)
                 for key, (spec, provider) in after_edges.get(inverse.get(consumer, consumer), {}).items()}
        for key in sorted(left.keys() | right.keys()):
            if left.get(key) == right.get(key):
                continue
            providers = {edge[1][0] for edge in (left.get(key), right.get(key))
                         if edge is not None and edge[1] is not None}
            if consumer not in impacted and not providers & impacted:
                return {"status": "RESOLUTION_FAILED", "code": "LOCK_UNRELATED_EDGE_DELTA",
                        "path": consumer, "dependency": key[1]}
            edge_changes += 1
    return {"status": "RESOLUTION_PASSED", "code": "LOCK_IMPACT_CLOSURE_MATCH",
            "changedPackageCount": len(delta), "changedEdgeCount": edge_changes,
            "impactedInstanceCount": len(impacted)}
