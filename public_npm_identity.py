"""Bind an anonymous public npm packument to an exact release and selected lock record."""
import base64
import hashlib
import re

PUBLIC_NPM_REGISTRY = "https://registry.npmjs.org"


class AdvisoryOnlyPackument(dict):
    """Fresh anonymous public response with a refused cookie. Never persist as identity evidence."""


def published_version(packument, name, version):
    if packument.get("name") != name:
        return None
    versions = packument.get("versions")
    record = versions.get(version) if isinstance(versions, dict) else None
    if not isinstance(record, dict) or record.get("name") != name or record.get("version") != version:
        return None
    dist = record.get("dist")
    expected = f"{PUBLIC_NPM_REGISTRY}/{name}/-/{name.rsplit('/', 1)[-1]}-{version}.tgz"
    return dist if isinstance(dist, dict) and dist.get("tarball") == expected else None


def matches_lock(packument, name, version, record, *, yarn=False):
    dist = published_version(packument, name, version)
    if (not dist or not isinstance(record, dict) or record.get("link") or record.get("inBundle") or record.get("bundled")
            or record.get("version") != version or record.get("name", name) != name):
        return False
    if yarn and "resolution" in record:
        # A Berry npm locator has no tarball URL. An alias, patch or custom
        # archive carries a different locator. Its checksum is for the Yarn zip.
        return record["resolution"] == f"{name}@npm:{version}" and "resolved" not in record
    integrity = record.get("integrity")
    if "integrity" in record:
        if not isinstance(integrity, str) or integrity != dist.get("integrity"):
            return False
        algorithm, _, encoded = integrity.partition("-")
        try:
            if (algorithm not in {"sha256", "sha384", "sha512"} or
                    len(base64.b64decode(encoded, validate=True)) != hashlib.new(algorithm).digest_size):
                return False
        except ValueError:
            return False
    resolved = record.get("resolved")
    if resolved is None:
        return bool(integrity)
    if not isinstance(resolved, str):
        return False
    url, separator, digest = resolved.partition("#")
    if separator and (not re.fullmatch("[0-9a-f]{40}", digest) or digest != dist.get("shasum")):
        return False
    if url == dist["tarball"]:
        return True
    # Classic Yarn's public mirror uses the same archive path. Require a
    # matching content identifier before equating these distinct origins.
    yarn_url = dist["tarball"].replace(PUBLIC_NPM_REGISTRY + "/", "https://registry.yarnpkg.com/", 1)
    return url == yarn_url and bool(integrity or digest)
