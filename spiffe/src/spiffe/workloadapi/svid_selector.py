"""
(C) Copyright 2021 Hewlett Packard Enterprise Development LP

Licensed under the Apache License, Version 2.0 (the "License"); you may
not use this file except in compliance with the License. You may obtain
a copy of the License at

https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations
under the License.
"""

"""
Reusable strategies for choosing a single X.509-SVID out of the list returned by the
Workload API, suitable for use as the ``svid_picker`` of an :class:`X509Source`.
"""

import threading
from typing import List, Optional, Tuple, Union

from cryptography.hazmat.primitives import hashes

from spiffe.errors import ArgumentError, PySpiffeError
from spiffe.spiffe_id.spiffe_id import SpiffeId
from spiffe.svid.x509_svid import X509Svid

__all__ = [
    'SvidSelectorError',
    'TargetSvidNotFoundError',
    'AmbiguousTargetSvidError',
    'TargetSvidSelector',
]

# An SVID entry is identified within an update by its leaf certificate together with its
# hint. The same leaf offered under two different hints is a separate Workload API entry.
SvidKey = Tuple[bytes, str]


class SvidSelectorError(PySpiffeError):
    """Base class for errors raised while selecting an X.509-SVID."""


class TargetSvidNotFoundError(SvidSelectorError):
    """Raised when no SVID in an update matches the requested SPIFFE ID (and hint)."""

    def __init__(self, target_spiffe_id: SpiffeId, hint: str = '') -> None:
        if hint:
            message = (
                f'No X.509-SVID matches SPIFFE ID {str(target_spiffe_id)!r} '
                f'with hint {hint!r}'
            )
        else:
            message = f'No X.509-SVID matches SPIFFE ID {str(target_spiffe_id)!r}'
        super().__init__(message)
        self.target_spiffe_id = target_spiffe_id
        self.hint = hint


class AmbiguousTargetSvidError(SvidSelectorError):
    """Raised when more than one distinct SVID matches the requested identity.

    The selector never guesses between matching SVIDs: an ambiguous target is a hard
    failure so that an application cannot silently run under the wrong identity.
    """

    def __init__(self, target_spiffe_id: SpiffeId, hint: str, count: int) -> None:
        hint_clause = f' with hint {hint!r}' if hint else ''
        super().__init__(
            f'{count} distinct X.509-SVIDs match SPIFFE ID '
            f'{str(target_spiffe_id)!r}{hint_clause}; expected exactly one'
        )
        self.target_spiffe_id = target_spiffe_id
        self.hint = hint
        self.count = count


def _svid_key(svid: X509Svid) -> SvidKey:
    """Returns the stable key of an SVID entry: leaf fingerprint plus its hint."""
    return svid.leaf.fingerprint(hashes.SHA256()), svid.hint


class TargetSvidSelector:
    """Pins an :class:`X509Source` to one fixed SPIFFE ID, optionally restricted to a hint.

    The selector is stateful and is meant to be passed as the ``svid_picker`` of an
    :class:`X509Source`, which invokes it on every Workload API update. It implements the
    application policy "always use this exact identity":

    - SVIDs are first filtered by the target :class:`SpiffeId`. When ``hint`` is provided,
      only SVIDs carrying that exact non-empty hint match; an SVID with an empty hint never
      matches a non-empty hint and empty-hint entries are never merged with hinted ones.
      When ``hint`` is left unset, SVIDs with any hint (including the empty hint) match the
      SPIFFE ID.
    - The Workload API "first SVID per hint" rule is preserved. For matching SVIDs that
      carry a non-empty hint, only the first entry for that hint in the update is kept;
      matching SVIDs that have an empty hint are each retained independently and are never
      deduplicated against one another or against hinted entries.
    - The logical identity is fixed to ``(SPIFFE ID, hint)`` once selected. Within that
      identity the concrete leaf certificate is held *sticky*: on later updates the same
      leaf is returned as long as it is present, regardless of list reordering or of other
      SVIDs appearing or disappearing, so a list change never silently swaps the identity.
    - If the held leaf disappears, the pin does not move to a different entry while more
      than one distinct candidate remains (that would be a guess). When exactly one
      distinct candidate for the same logical identity remains, it is treated as the
      renewed/rotated certificate and the sticky leaf is updated to it. When no candidate
      remains the target is reported as missing.

    Failures are explicit. :meth:`pick` raises :class:`TargetSvidNotFoundError` when the
    target is absent and :class:`AmbiguousTargetSvidError` when the target is not unique.
    Inside an :class:`X509Source` such an exception makes the source fail closed (it is
    closed permanently and does not recover on a later matching update); callers using the
    selector directly can inspect :attr:`selected` for the last good SVID.
    """

    def __init__(
        self, target_spiffe_id: Union[str, SpiffeId], hint: Optional[str] = None
    ) -> None:
        """Creates a selector for a fixed target identity.

        Args:
            target_spiffe_id: The SPIFFE ID the application must present. Accepted as a
                :class:`SpiffeId` or a ``spiffe://`` string.
            hint: Optional non-empty hint that further restricts the match. When set, only
                SVIDs with this exact hint are eligible. Leave unset (or ``None``) to match
                the SPIFFE ID regardless of hint. An empty string is rejected: use ``None``
                to express "no hint constraint", since an empty hint on an SVID means
                "no hint" and must not be confused with a requested hint.

        Raises:
            ArgumentError: If ``hint`` is an empty string.
            SpiffeIdError: If ``target_spiffe_id`` is not a valid SPIFFE ID.
        """
        if hint is not None and hint == '':
            raise ArgumentError(
                'hint cannot be an empty string; use None to match without a hint constraint'
            )

        self._target_spiffe_id = (
            target_spiffe_id
            if isinstance(target_spiffe_id, SpiffeId)
            else SpiffeId(target_spiffe_id)
        )
        self._hint = hint or ''
        # Leaf key (fingerprint + hint) currently held sticky. ``None`` until the first
        # successful selection. The logical (SPIFFE ID, hint) identity itself never changes.
        self._pinned_key: Optional[SvidKey] = None
        self._selected: Optional[X509Svid] = None
        self._lock = threading.Lock()

    @property
    def target_spiffe_id(self) -> SpiffeId:
        """Returns the SPIFFE ID this selector is pinned to."""
        return self._target_spiffe_id

    @property
    def hint(self) -> str:
        """Returns the required hint, or an empty string when no hint constraint is set."""
        return self._hint

    @property
    def selected(self) -> Optional[X509Svid]:
        """Returns the last SVID chosen, or ``None`` if selection has never succeeded."""
        with self._lock:
            return self._selected

    def pick(self, svids: List[X509Svid]) -> X509Svid:
        """Selects the target SVID from one Workload API update.

        Args:
            svids: The list of SVIDs delivered in an X509Context.

        Returns:
            The pinned target SVID.

        Raises:
            TargetSvidNotFoundError: If no SVID matches the target SPIFFE ID and hint.
            AmbiguousTargetSvidError: If the target is represented by more than one
                distinct entry and the currently held leaf is not among them, so choosing
                one would be a guess.
        """
        with self._lock:
            candidates = [svid for svid in svids if self._matches(svid)]
            if not candidates:
                # No candidate for the logical identity: fail loudly while keeping the last
                # good SVID available through ``selected``. Do not switch to another entry.
                raise TargetSvidNotFoundError(self._target_spiffe_id, self._hint)

            # Sticky check first, against the raw candidates: as long as the exact leaf+hint
            # already committed is still offered, keep it. This takes precedence over list
            # order so a reordering (or an earlier duplicate-hint entry) can never move the
            # pin to another identity.
            if self._pinned_key is not None:
                for svid in candidates:
                    if _svid_key(svid) == self._pinned_key:
                        self._selected = svid
                        return svid

            # No live pin. Apply the Workload API first-SVID-per-hint rule, which keeps the
            # first entry of each non-empty hint and never collapses empty-hint entries.
            distinct = self._first_entry_per_hint(candidates)
            if len(distinct) > 1:
                # Several distinct entries represent the target identity; choosing one would
                # be a guess, so fail rather than silently assuming a different identity.
                raise AmbiguousTargetSvidError(
                    self._target_spiffe_id, self._hint, len(distinct)
                )

            chosen = distinct[0]
            self._pinned_key = _svid_key(chosen)
            self._selected = chosen
            return chosen

    def __call__(self, svids: List[X509Svid]) -> X509Svid:
        """Alias for :meth:`pick` so the instance can be passed directly as ``svid_picker``."""
        return self.pick(svids)

    def _matches(self, svid: X509Svid) -> bool:
        if svid.spiffe_id != self._target_spiffe_id:
            return False
        if self._hint:
            # An empty hint never satisfies a requested non-empty hint, and hinted
            # candidates are never merged with empty-hint ones.
            return svid.hint == self._hint
        return True

    @staticmethod
    def _first_entry_per_hint(svids: List[X509Svid]) -> List[X509Svid]:
        """Applies the Workload API first-SVID-per-hint rule to already-matching SVIDs.

        For every non-empty hint, only the first entry carrying that hint is kept. Entries
        without a hint are always kept and are never collapsed together, so two empty-hint
        SVIDs (or an empty-hint and a hinted one) remain distinct candidates. First-seen
        order is preserved.
        """
        first_seen: List[X509Svid] = []
        seen_hints: set[str] = set()
        seen_empty_keys: set[SvidKey] = set()
        for svid in svids:
            if svid.hint:
                if svid.hint in seen_hints:
                    continue
                seen_hints.add(svid.hint)
                first_seen.append(svid)
            else:
                key = _svid_key(svid)
                if key in seen_empty_keys:
                    continue
                seen_empty_keys.add(key)
                first_seen.append(svid)
        return first_seen
