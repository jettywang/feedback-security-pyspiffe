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

import datetime
from typing import List, cast

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from spiffe import X509Svid
from spiffe.errors import ArgumentError
from spiffe.spiffe_id.spiffe_id import SpiffeId
from spiffe.workloadapi.svid_selector import (
    AmbiguousTargetSvidError,
    TargetSvidNotFoundError,
    TargetSvidSelector,
)
from testutils.certs import CHAIN1, CHAIN2, KEY1, KEY2

SERVICE = 'spiffe://example.org/service'
SERVICE2 = 'spiffe://example.org/service2'


def _svid(chain: bytes, key: bytes, hint: str = '') -> X509Svid:
    return X509Svid.parse_raw(chain, key, hint=hint)


def _fresh_leaf_svid(spiffe_id: str, hint: str = '') -> X509Svid:
    """Builds an SVID with a freshly generated leaf carrying the given SPIFFE ID.

    Each call yields a distinct leaf certificate, which lets tests model rotations and
    multiple distinct SVIDs sharing one SPIFFE ID without touching the on-disk fixtures.
    """
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'test')])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.UniformResourceIdentifier(spiffe_id)]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    return X509Svid(SpiffeId(spiffe_id), [cert], key, hint=hint)


def test_picks_unique_svid_by_spiffe_id() -> None:
    target = _svid(CHAIN1, KEY1, hint='internal')
    other = _svid(CHAIN2, KEY2, hint='external')
    selector = TargetSvidSelector(SERVICE)

    picked = selector.pick([other, target])

    assert picked is target
    assert picked.spiffe_id == SpiffeId(SERVICE)
    assert selector.selected is target


def test_accepts_spiffe_id_instance() -> None:
    target = _svid(CHAIN1, KEY1)
    selector = TargetSvidSelector(SpiffeId(SERVICE))

    assert selector.pick([target]) is target


def test_hint_constraint_requires_exact_non_empty_hint() -> None:
    hinted = _svid(CHAIN1, KEY1, hint='internal')
    empty_hint = _svid(CHAIN1, KEY1)
    selector = TargetSvidSelector(SERVICE, hint='internal')

    assert selector.hint == 'internal'
    assert selector.pick([empty_hint, hinted]) is hinted


def test_empty_hint_candidate_does_not_satisfy_requested_hint() -> None:
    empty_hint = _svid(CHAIN1, KEY1)
    selector = TargetSvidSelector(SERVICE, hint='internal')

    with pytest.raises(TargetSvidNotFoundError) as err:
        selector.pick([empty_hint])

    assert SERVICE in str(err.value)
    assert "'internal'" in str(err.value)
    assert selector.selected is None


def test_empty_hint_string_constructor_is_rejected() -> None:
    with pytest.raises(ArgumentError):
        TargetSvidSelector(SERVICE, hint='')


def test_without_hint_constraint_matches_any_hint() -> None:
    hinted = _svid(CHAIN1, KEY1, hint='internal')
    selector = TargetSvidSelector(SERVICE)

    assert selector.pick([hinted]) is hinted


def test_target_spiffe_id_absent_raises_not_found() -> None:
    other = _svid(CHAIN2, KEY2)
    selector = TargetSvidSelector(SERVICE)

    with pytest.raises(TargetSvidNotFoundError) as err:
        selector.pick([other])

    assert SERVICE in str(err.value)


def test_multiple_distinct_matches_raise_ambiguous() -> None:
    first = _fresh_leaf_svid(SERVICE, hint='a')
    second = _fresh_leaf_svid(SERVICE, hint='b')
    selector = TargetSvidSelector(SERVICE)

    with pytest.raises(AmbiguousTargetSvidError) as err:
        selector.pick([first, second])

    assert err.value.count == 2
    # nothing was chosen, so no identity gets silently assumed
    assert selector.selected is None


def test_repeated_same_leaf_entries_are_not_ambiguous() -> None:
    target = _svid(CHAIN1, KEY1, hint='a')
    same_material = _svid(CHAIN1, KEY1, hint='a')
    selector = TargetSvidSelector(SERVICE)

    assert selector.pick([target, same_material]) is target


def test_reordering_does_not_switch_identity() -> None:
    # The pin is established while the target is unique. A later update introduces a second
    # distinct leaf with the same SPIFFE ID and reorders the list; the pinned leaf must win
    # instead of silently switching to the newcomer or the first entry.
    first = _fresh_leaf_svid(SERVICE, hint='a')
    second = _fresh_leaf_svid(SERVICE, hint='b')
    unrelated = _svid(CHAIN2, KEY2)
    selector = TargetSvidSelector(SERVICE)

    assert selector.pick([unrelated, first]) is first

    assert selector.pick([second, first, unrelated]) is first
    assert selector.pick([first, second]) is first
    assert selector.pick([second, first]).hint == 'a'


def test_pinned_identity_survives_unrelated_updates() -> None:
    target = _svid(CHAIN1, KEY1, hint='internal')
    other = _svid(CHAIN2, KEY2, hint='external')
    selector = TargetSvidSelector(SERVICE, hint='internal')

    assert selector.pick([target, other]) is target
    assert selector.pick([other, target]) is target


def test_target_disappearing_then_reappearing_repins_same_identity() -> None:
    target = _svid(CHAIN1, KEY1, hint='internal')
    other = _svid(CHAIN2, KEY2, hint='external')
    selector = TargetSvidSelector(SERVICE, hint='internal')

    assert selector.pick([target, other]) is target

    # Target entry removed: explicit not-found rather than falling back to another identity.
    with pytest.raises(TargetSvidNotFoundError):
        selector.pick([other])
    assert selector.selected is target

    # Reappears as the unique match: pinned again, still the same leaf material.
    repinned = selector.pick([other, target])
    assert repinned is target


def test_hint_removal_on_target_is_treated_as_disappearance() -> None:
    hinted = _svid(CHAIN1, KEY1, hint='internal')
    no_hint = _svid(CHAIN1, KEY1)
    selector = TargetSvidSelector(SERVICE, hint='internal')

    assert selector.pick([hinted]) is hinted
    with pytest.raises(TargetSvidNotFoundError):
        selector.pick([no_hint])
    # Restoring the hinted entry recovers the original pinned identity.
    assert selector.pick([no_hint, hinted]) is hinted


def test_pinned_leaf_rotation_follows_the_renewed_certificate() -> None:
    # Rotation means the old leaf is replaced by a renewed leaf with the same identity/hint.
    old_leaf = _fresh_leaf_svid(SERVICE, hint='internal')
    renewed_leaf = _fresh_leaf_svid(SERVICE, hint='internal')
    other = _svid(CHAIN2, KEY2)
    selector = TargetSvidSelector(SERVICE, hint='internal')

    assert selector.pick([old_leaf, other]) is old_leaf

    rotated = selector.pick([renewed_leaf, other])
    assert rotated is renewed_leaf
    assert rotated.hint == 'internal'
    assert selector.selected is renewed_leaf


def test_reappearance_with_two_candidates_fails_instead_of_guessing() -> None:
    pinned = _fresh_leaf_svid(SERVICE, hint='a')
    distinct = _fresh_leaf_svid(SERVICE, hint='b')
    another = _fresh_leaf_svid(SERVICE, hint='c')
    third = _svid(CHAIN2, KEY2)
    selector = TargetSvidSelector(SERVICE)

    assert selector.pick([pinned, third]) is pinned

    # The pinned leaf vanished; two distinct matches now compete for the same identity.
    with pytest.raises(AmbiguousTargetSvidError):
        selector.pick([distinct, another])
    # The last good SVID remains inspectable; no new identity was assumed.
    assert selector.selected is pinned


def test_same_hint_sticky_pin_survives_reordering() -> None:
    # Once an entry is pinned, reordering the same two same-hint leaves must never move the
    # pin to the other one, even though the first entry of the update would now differ.
    first = _fresh_leaf_svid(SERVICE, hint='internal')
    alternate = _fresh_leaf_svid(SERVICE, hint='internal')
    selector = TargetSvidSelector(SERVICE, hint='internal')

    assert selector.pick([first, alternate]) is first
    assert selector.pick([alternate, first]) is first
    assert selector.selected is first


def test_first_entry_per_hint_wins_even_without_an_existing_pin() -> None:
    # On a selection with no live pin, the first entry for the requested non-empty hint
    # wins, mirroring the protocol-level de-duplication performed by the Workload API client.
    first = _fresh_leaf_svid(SERVICE, hint='internal')
    second = _fresh_leaf_svid(SERVICE, hint='internal')
    selector = TargetSvidSelector(SERVICE, hint='internal')

    assert selector.pick([first, second]) is first
    assert selector.selected is first

    # A fresh selector sees the entries in the opposite order and pins that first entry.
    reordered_selector = TargetSvidSelector(SERVICE, hint='internal')
    assert reordered_selector.pick([second, first]) is second


def test_selector_is_callable_for_x509_source_picker() -> None:
    target = _svid(CHAIN1, KEY1, hint='internal')
    selector = TargetSvidSelector(SERVICE, hint='internal')

    picked: X509Svid = cast(X509Svid, selector([target, _svid(CHAIN2, KEY2, hint='external')]))
    assert picked is target


def test_empty_hint_candidates_are_not_merged_with_hinted_ones() -> None:
    # No hint constraint: an empty-hint SVID and a hinted SVID with the same ID are two
    # distinct candidates and must not be merged into one selection.
    empty_hint = _fresh_leaf_svid(SERVICE)
    hinted = _fresh_leaf_svid(SERVICE, hint='internal')
    selector = TargetSvidSelector(SERVICE)

    with pytest.raises(AmbiguousTargetSvidError):
        selector.pick([empty_hint, hinted])


def test_two_empty_hint_candidates_with_same_id_are_distinct() -> None:
    # Empty-hint entries are never collapsed together, even when the SPIFFE ID matches.
    first = _fresh_leaf_svid(SERVICE)
    second = _fresh_leaf_svid(SERVICE)
    selector = TargetSvidSelector(SERVICE)

    with pytest.raises(AmbiguousTargetSvidError):
        selector.pick([first, second])


def test_update_sequence_reorder_disappear_reappear() -> None:
    # End-to-end update sequence over one selector instance, using distinct hints so that
    # the entries represent genuinely different candidate identities.
    service_a = _fresh_leaf_svid(SERVICE, hint='a')
    service_b = _fresh_leaf_svid(SERVICE, hint='b')
    other = _svid(CHAIN2, KEY2, hint='external')
    selector = TargetSvidSelector(SERVICE)
    updates: List[List[X509Svid]] = []

    # Update 1: target is unique -> service_a is pinned.
    updates.append([other, service_a])
    assert selector.pick(updates[-1]) is service_a
    # Update 2: service_b with the same SPIFFE ID appears and the list is reordered.
    # Because service_a is still present, the sticky pin wins; no switch to service_b.
    updates.append([service_b, service_a, other])
    assert selector.pick(updates[-1]) is service_a
    # Update 3: service_a is gone, only service_b remains for this SPIFFE ID. With a single
    # distinct candidate it is treated as the renewed identity rather than guessed among.
    renewed = selector.pick([service_b, other])
    assert renewed is service_b
    # Update 4: both leaves return; the now-pinned service_b is held, service_a does not
    # take over even when listed first.
    assert selector.pick([service_a, service_b]) is service_b
    # Update 5: the whole SPIFFE ID disappears -> explicit not-found, last good SVID kept.
    with pytest.raises(TargetSvidNotFoundError):
        selector.pick([other])
    assert selector.selected is service_b
    # Update 6: service_b reappears uniquely -> re-pinned to the same leaf.
    assert selector.pick([service_b]) is service_b


def test_after_pin_is_lost_two_distinct_hints_fail_closed() -> None:
    # Once the pinned leaf is gone, if two distinct leaves with different non-empty hints
    # share the SPIFFE ID, selection fails rather than guessing either one.
    pinned = _fresh_leaf_svid(SERVICE, hint='a')
    competitor_b = _fresh_leaf_svid(SERVICE, hint='b')
    competitor_c = _fresh_leaf_svid(SERVICE, hint='c')
    other = _svid(CHAIN2, KEY2)
    selector = TargetSvidSelector(SERVICE)

    assert selector.pick([pinned, other]) is pinned
    # The pinned SPIFFE ID disappears entirely first.
    with pytest.raises(TargetSvidNotFoundError):
        selector.pick([other])
    # It comes back, but now two distinct hinted leaves compete for the same identity.
    with pytest.raises(AmbiguousTargetSvidError):
        selector.pick([competitor_b, competitor_c])
    assert selector.selected is pinned
