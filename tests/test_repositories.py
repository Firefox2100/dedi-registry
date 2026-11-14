"""
Tests for the MongoDB repositories, run against the real database the other tests use.

Every test creates records under fresh IDs and only asserts on those, so they are safe
to run next to the end-to-end tests and against a database that already holds data.
"""

import uuid
from datetime import datetime, timezone

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from dedi_registry.database import get_active_db
from dedi_registry.etc.consts import PH
from dedi_registry.etc.enums import RecordAction, RecordStatus
from dedi_registry.etc.utils import reformat_pem
from dedi_registry.model.network import Network, NetworkAudit, NetworkAuditRequestDetail
from dedi_registry.model.node import Node
from dedi_registry.model.user import User

PEM = reformat_pem(ec.generate_private_key(ec.SECP384R1()).public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
).decode())


@pytest.fixture(scope='module')
async def db(app_manager):
    return get_active_db()


def make_network(token: str, node_count: int = 1, **overrides) -> Network:
    data = {
        'networkId': uuid.uuid4(),
        'status': RecordStatus.PENDING,
        'networkName': f'Repo {token}',
        'description': f'Repository test {token}',
        'publicKey': PEM,
        'nodes': [
            Node(
                nodeId=uuid.uuid4(),
                nodeName=f'Node {index}',
                url=f'https://{token}-{index}.repo.example',
                description='',
                publicKey=PEM,
            ) for index in range(node_count)
        ],
    }
    data.update(overrides)
    return Network(**data)


def make_audit(network: Network, version: int) -> NetworkAudit:
    return NetworkAudit(
        networkId=network.network_id,
        version=version,
        action=RecordAction.CREATE if version == 0 else RecordAction.UPDATE,
        actorNode='Administrator',
        timestamp=datetime.now(timezone.utc),
        patch=[],
        hashBefore=None,
        hashAfter='sha256:abc',
        requestDetail=NetworkAuditRequestDetail(ipAddress='127.0.0.1', userAgent='tests'),
    )


class TestNetworkRepository:
    async def test_save_and_get_round_trip(self, db):
        network = make_network(uuid.uuid4().hex)
        await db.networks.save(network)

        loaded = await db.networks.get(network.network_id)

        assert loaded.network_name == network.network_name
        assert loaded.status == RecordStatus.PENDING
        assert len(loaded.nodes) == 1

    async def test_get_unknown_network(self, db):
        assert await db.networks.get(uuid.uuid4()) is None

    async def test_save_twice_updates_in_place(self, db):
        network = make_network(uuid.uuid4().hex)
        await db.networks.save(network)
        network.description = 'Changed'
        await db.networks.save(network)

        assert (await db.networks.get(network.network_id)).description == 'Changed'
        assert len(await db.networks.search(name=network.network_name)) == 1

    async def test_update_status(self, db):
        network = make_network(uuid.uuid4().hex)
        await db.networks.save(network)

        await db.networks.update_status(network.network_id, RecordStatus.ACTIVE)

        assert (await db.networks.get(network.network_id)).status == RecordStatus.ACTIVE

    async def test_update_replaces_the_stored_network(self, db):
        network = make_network(uuid.uuid4().hex, node_count=2)
        await db.networks.save(network)

        network.nodes = network.nodes[:1]
        network.network_name = f'{network.network_name} renamed'
        await db.networks.update(network)

        loaded = await db.networks.get(network.network_id)
        assert len(loaded.nodes) == 1
        assert loaded.network_name.endswith('renamed')

    async def test_delete(self, db):
        network = make_network(uuid.uuid4().hex)
        await db.networks.save(network)

        await db.networks.delete(str(network.network_id))

        assert await db.networks.get(network.network_id) is None

    async def test_search_filters_combine(self, db):
        token = uuid.uuid4().hex
        match = make_network(token)
        other = make_network(uuid.uuid4().hex, networkName=f'Repo {token} other',
                             description='something else')
        await db.networks.save(match)
        await db.networks.save(other)

        by_name = await db.networks.search(name=token.upper())
        assert {n.network_id for n in by_name} == {match.network_id, other.network_id}

        by_description = await db.networks.search(description=f'Repository test {token}')
        assert [n.network_id for n in by_description] == [match.network_id]

        by_url = await db.networks.search(url=f'{token}-0.repo.example')
        assert [n.network_id for n in by_url] == [match.network_id]

        both = await db.networks.search(name=token, description='something else')
        assert [n.network_id for n in both] == [other.network_id]

        assert await db.networks.search(name=f'no-such-{uuid.uuid4().hex}') == []

    async def test_counts_by_status(self, db):
        before_all = await db.networks.count()
        before_active = await db.networks.count(RecordStatus.ACTIVE)
        before_nodes = await db.networks.count_nodes(RecordStatus.ACTIVE)

        active = make_network(uuid.uuid4().hex, node_count=3, status=RecordStatus.ACTIVE)
        pending = make_network(uuid.uuid4().hex, node_count=2)
        await db.networks.save(active)
        await db.networks.save(pending)

        assert await db.networks.count() == before_all + 2
        assert await db.networks.count(RecordStatus.ACTIVE) == before_active + 1
        # Nodes of networks in other states are not counted
        assert await db.networks.count_nodes(RecordStatus.ACTIVE) == before_nodes + 3

    async def test_filter_by_status_and_name(self, db):
        token = uuid.uuid4().hex
        active = make_network(token, status=RecordStatus.ACTIVE)
        pending = make_network(token)
        await db.networks.save(active)
        await db.networks.save(pending)

        networks, _, _ = await db.networks.filter(status=RecordStatus.ACTIVE, name=token, limit=0)

        assert [n.network_id for n in networks] == [active.network_id]

    async def test_name_filter_is_literal(self, db):
        token = uuid.uuid4().hex
        await db.networks.save(make_network(token))

        networks, _, _ = await db.networks.filter(name='.*', limit=0)

        assert all('.*' in n.network_name for n in networks)

    async def test_pagination_in_both_directions(self, db):
        token = uuid.uuid4().hex
        created = [make_network(token) for _ in range(5)]
        for network in created:
            await db.networks.save(network)
        expected = [network.network_id for network in created]

        first, first_cursor, last_cursor = await db.networks.filter(name=token, limit=2)
        assert [n.network_id for n in first] == expected[:2]
        assert last_cursor is not None

        second, _, second_last = await db.networks.filter(
            name=token, limit=2, cursor_id=last_cursor,
        )
        assert [n.network_id for n in second] == expected[2:4]

        third, _, third_last = await db.networks.filter(
            name=token, limit=2, cursor_id=second_last,
        )
        assert [n.network_id for n in third] == expected[4:]
        assert third_last is None

        # Walking back keeps the original order
        back, _, _ = await db.networks.filter(
            name=token, limit=2, cursor_id=second_last, forward=False,
        )
        assert [n.network_id for n in back] == expected[1:3]

        unlimited, _, none_left = await db.networks.filter(name=token, limit=0)
        assert [n.network_id for n in unlimited] == expected
        assert none_left is None

    async def test_invalid_cursor_is_rejected(self, db):
        with pytest.raises(ValueError):
            await db.networks.filter(cursor_id='not-an-object-id')


class TestAuditRepository:
    async def test_save_get_and_list_in_version_order(self, db):
        network = make_network(uuid.uuid4().hex)
        await db.audits.save(make_audit(network, 1))
        await db.audits.save(make_audit(network, 0))

        assert (await db.audits.get(str(network.network_id), 0)).action == RecordAction.CREATE
        assert await db.audits.get(str(network.network_id), 9) is None

        audits = await db.audits.get_network_audits(network.network_id)
        assert [audit.version for audit in audits] == [0, 1]

    async def test_a_version_cannot_be_recorded_twice(self, db):
        network = make_network(uuid.uuid4().hex)
        await db.audits.save(make_audit(network, 0))

        with pytest.raises(ValueError):
            await db.audits.save(make_audit(network, 0))

        assert len(await db.audits.get_network_audits(network.network_id)) == 1


class TestUserRepository:
    async def test_save_get_and_password_check(self, db):
        username = f'repo_{uuid.uuid4().hex}'
        await db.users.save(User(username=username, password=PH.hash('s3cret')))

        user = await db.users.get(username)

        assert user.validate_password('s3cret')
        assert not user.validate_password('wrong')
        assert await db.users.get(f'missing_{uuid.uuid4().hex}') is None

    async def test_update_changes_the_password(self, db):
        username = f'repo_{uuid.uuid4().hex}'
        await db.users.save(User(username=username, password=PH.hash('old')))

        await db.users.update(User(username=username, password=PH.hash('new')))

        user = await db.users.get(username)
        assert user.validate_password('new')
        assert not user.validate_password('old')

    async def test_update_does_not_create_users(self, db):
        username = f'repo_{uuid.uuid4().hex}'

        await db.users.update(User(username=username, password=PH.hash('x')))

        assert await db.users.get(username) is None

    async def test_delete_and_listing(self, db):
        username = f'repo_{uuid.uuid4().hex}'
        await db.users.save(User(username=username, password=PH.hash('x')))
        assert username in [user.username for user in await db.users.filter()]

        await db.users.delete(username)

        assert await db.users.get(username) is None
        assert username not in [user.username for user in await db.users.filter()]
