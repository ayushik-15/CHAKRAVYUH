"""CHAKRAVYUH Arbiter — Plane isolation & endpoint ACL enforcement.

The :class:`PlaneRouter` ensures that each plane (Red, Blue, Observer) can
only access the endpoints designated for its role.  This provides a hard
security boundary independent of any application-level authorisation logic.
"""

from __future__ import annotations

import fnmatch
import logging

from fastapi import HTTPException, status

logger = logging.getLogger("arbiter.isolation")


# ── Endpoint ACLs ────────────────────────────────────────────────────────────
# Patterns use ``fnmatch``-style globs so that ``/round/{id}/status`` is
# written as ``/round/*/status``.

_PLANE_ACLS: dict[str, list[str]] = {
    "red": [
        "/round/new",
        "/round/*/commit",
        "/round/*/payload",
        "/round/*/reveal",
        "/round/*/status",
        "/arbiter/pubkey",
    ],
    "blue": [
        "/round/*/verdict",
        "/round/*/scores",
        "/round/*/status",
    ],
    "observer": [
        "/round/*/status",
        "/round/*/verify",
        "/log/*",
    ],
}


class PlaneRouter:
    """Validates that a given plane is allowed to access a specific endpoint.

    Usage::

        router = PlaneRouter()
        if not router.check_access("red", "/round/abc/commit"):
            raise HTTPException(403)
    """

    def __init__(
        self,
        acls: dict[str, list[str]] | None = None,
    ) -> None:
        self._acls = acls or _PLANE_ACLS

    def check_access(self, plane: str, endpoint: str) -> bool:
        """Return ``True`` if *plane* is permitted to access *endpoint*.

        Args:
            plane: The plane identity string (e.g. ``"red"``, ``"blue"``,
                ``"observer"``).  Case-insensitive.
            endpoint: The request path (e.g. ``"/round/abc/commit"``).

        Returns:
            ``True`` if at least one ACL pattern for *plane* matches
            *endpoint*; ``False`` otherwise.
        """
        patterns = self._acls.get(plane.lower(), [])
        return any(fnmatch.fnmatch(endpoint, pat) for pat in patterns)

    def enforce(self, plane: str | None, endpoint: str) -> None:
        """Raise ``403 Forbidden`` if *plane* may not access *endpoint*.

        If *plane* is ``None`` (unauthenticated request), access is denied
        unconditionally.

        Args:
            plane: Caller's plane identity, or ``None``.
            endpoint: The request path.

        Raises:
            HTTPException: 403 if access is denied.
        """
        if plane is None:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Plane identity required — provide a valid JWT.",
            )
        if not self.check_access(plane, endpoint):
            logger.warning(
                "Access DENIED — plane=%s endpoint=%s", plane, endpoint,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"Plane '{plane}' is not authorised to access {endpoint}."
                ),
            )

