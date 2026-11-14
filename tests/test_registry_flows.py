"""
End-to-end tests for the paths the smoke tests do not reach: API error handling,
the administrator actions and their idempotence, and the public listing.

Each test module run registers its own networks with unique IDs, so these tests
do not depend on the state left behind by smoke_test.py or earlier runs.
"""

import hashlib
import json
import uuid

import httpx
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from httpx import ASGITransport

from dedi_registry.etc.utils import reformat_pem

BASE_URL = 'http://localhost:5876'
USER_AGENT = 'DediRegistryFlowTest/1.0'


def _pem(key: ec.EllipticCurvePrivateKey) -> str:
    return reformat_pem(key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode())


def _solve(nonce: str, difficulty: int) -> int:
    counter = 0
    while True:
        digest = hashlib.sha256(f'{nonce}{counter}'.encode()).hexdigest()
        if bin(int(digest, 16))[2:].zfill(256).startswith('0' * difficulty):
            return counter
        counter += 1


class Registered:
    """A network registered through the API, with the keys needed to update it."""

    def __init__(self):
        self.network_id = str(uuid.uuid4())
        self.node_id = str(uuid.uuid4())
        self.name = f'Flow Network {self.network_id}'
        self.network_key = ec.generate_private_key(ec.SECP384R1())
        self.node_key = ec.generate_private_key(ec.SECP384R1())

    def payload(self, **overrides) -> dict:
        data = {
            'networkId': self.network_id,
            'networkName': self.name,
            'description': 'Registered by the flow tests.',
            'publicKey': _pem(self.network_key),
            'nodes': [{
                'nodeId': self.node_id,
                'nodeName': 'Flow Node',
                'url': 'http://localhost:5901',
                'description': '',
                'publicKey': _pem(self.node_key),
            }],
        }
        data.update(overrides)
        return data

    def sign(self, data: dict) -> str:
        data = {**data, 'nodes': sorted(data['nodes'], key=lambda node: node['nodeId'])}
        serialised = json.dumps(data, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
        return self.network_key.sign(
            serialised.encode(),
            ec.ECDSA(hashes.SHA384()),
        ).hex()

    async def put(self, client: httpx.AsyncClient, data: dict, path_id: str | None = None):
        return await client.put(
            f'/api/v1/networks/{path_id or self.network_id}',
            json=data,
            headers={'Node-ID': self.node_id, 'Node-Signature': self.sign(data)},
        )


def _client(manager) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=ASGITransport(app=manager.app),
        base_url=BASE_URL,
        headers={'User-Agent': USER_AGENT},
    )


@pytest.fixture
async def visitor(app_manager):
    async with _client(app_manager) as client:
        yield client


@pytest.fixture
async def admin(app_manager):
    async with _client(app_manager) as client:
        await client.get('/admin/login')
        response = await client.post(
            '/admin/login',
            data={
                'username': 'test_admin',
                'password': 'test_password',
                'csrftoken': client.cookies.get('csrftoken'),
            },
            headers={'Referer': f'{BASE_URL}/admin/login'},
        )
        assert response.status_code == 303
        yield client


async def register(client: httpx.AsyncClient, **overrides) -> Registered:
    challenge = (await client.get('/api/v1/challenge')).json()
    solution = _solve(challenge['nonce'], challenge['difficulty'])

    registered = Registered()
    response = await client.post(
        '/api/v1/networks',
        json=registered.payload(**overrides),
        headers={'Node-ID': registered.node_id},
        params={'nonce': challenge['nonce'], 'solution': str(solution)},
    )
    assert response.status_code == 201, response.text

    return registered


async def admin_action(admin: httpx.AsyncClient, network_id: str, action: str, **form):
    return await admin.post(
        f'/admin/networks/{network_id}/{action}',
        data={'csrftoken': admin.cookies.get('csrftoken'), **form},
        headers={'Referer': f'{BASE_URL}/networks/{network_id}'},
    )


async def status_of(client: httpx.AsyncClient, network_id: str) -> str:
    return (await client.get(f'/api/v1/networks/{network_id}')).json()['status']


class TestRegistrationErrors:
    async def test_unknown_challenge_is_rejected(self, visitor):
        registered = Registered()
        response = await visitor.post(
            '/api/v1/networks',
            json=registered.payload(),
            headers={'Node-ID': registered.node_id},
            params={'nonce': 'never-issued', 'solution': '1'},
        )

        assert response.status_code == 403
        assert 'challenge' in response.json()['detail'].lower()

    async def test_wrong_solution_is_rejected(self, visitor):
        challenge = (await visitor.get('/api/v1/challenge')).json()
        wrong = str(_solve(challenge['nonce'], challenge['difficulty']) + 1)
        # A neighbouring counter almost never also solves it; make sure it does not
        while _solves(challenge, wrong):
            wrong = str(int(wrong) + 1)

        registered = Registered()
        response = await visitor.post(
            '/api/v1/networks',
            json=registered.payload(),
            headers={'Node-ID': registered.node_id},
            params={'nonce': challenge['nonce'], 'solution': wrong},
        )

        assert response.status_code == 403
        assert 'solution' in response.json()['detail'].lower()

    async def test_duplicate_network_conflicts(self, visitor):
        existing = await register(visitor)

        challenge = (await visitor.get('/api/v1/challenge')).json()
        response = await visitor.post(
            '/api/v1/networks',
            json=existing.payload(),
            headers={'Node-ID': existing.node_id},
            params={
                'nonce': challenge['nonce'],
                'solution': str(_solve(challenge['nonce'], challenge['difficulty'])),
            },
        )

        assert response.status_code == 409

    async def test_sender_must_belong_to_network(self, visitor):
        challenge = (await visitor.get('/api/v1/challenge')).json()
        registered = Registered()
        response = await visitor.post(
            '/api/v1/networks',
            json=registered.payload(),
            headers={'Node-ID': str(uuid.uuid4())},
            params={
                'nonce': challenge['nonce'],
                'solution': str(_solve(challenge['nonce'], challenge['difficulty'])),
            },
        )

        assert response.status_code == 400


def _solves(challenge: dict, solution: str) -> bool:
    digest = hashlib.sha256(f'{challenge["nonce"]}{solution}'.encode()).hexdigest()
    return bin(int(digest, 16))[2:].zfill(256).startswith('0' * challenge['difficulty'])


class TestNetworkLookup:
    async def test_unknown_network_is_404(self, visitor):
        missing = str(uuid.uuid4())

        assert (await visitor.get(f'/api/v1/networks/{missing}')).status_code == 404
        assert (await visitor.get(f'/api/v1/networks/{missing}/audits')).status_code == 404

    async def test_audit_trail_records_registration(self, visitor):
        registered = await register(visitor)

        audits = (await visitor.get(f'/api/v1/networks/{registered.network_id}/audits')).json()

        assert len(audits) == 1
        assert audits[0]['action'] == 'create'
        assert audits[0]['actorNode'] == registered.node_id


class TestNetworkUpdateErrors:
    async def test_path_and_payload_ids_must_match(self, visitor):
        registered = await register(visitor)
        other = str(uuid.uuid4())

        response = await registered.put(visitor, registered.payload(), path_id=other)

        assert response.status_code == 400

    async def test_unknown_network_cannot_be_updated(self, visitor):
        registered = Registered()

        response = await registered.put(visitor, registered.payload())

        assert response.status_code == 404

    async def test_sender_must_remain_in_network(self, visitor):
        registered = await register(visitor)
        other_node = {
            'nodeId': str(uuid.uuid4()),
            'nodeName': 'Someone else',
            'url': 'http://localhost:5902',
            'description': '',
            'publicKey': _pem(registered.node_key),
        }

        response = await registered.put(visitor, registered.payload(nodes=[other_node]))

        assert response.status_code == 400

    async def test_bad_signature_is_rejected(self, visitor):
        registered = await register(visitor)
        data = registered.payload(description='Changed')

        response = await visitor.put(
            f'/api/v1/networks/{registered.network_id}',
            json=data,
            headers={
                'Node-ID': registered.node_id,
                'Node-Signature': Registered().sign(data),
            },
        )

        assert response.status_code == 403
        assert await status_of(visitor, registered.network_id) == 'pending'

    async def test_update_without_changes_is_rejected(self, visitor):
        registered = await register(visitor)

        response = await registered.put(visitor, registered.payload())

        assert response.status_code == 400
        assert 'no changes' in response.json()['detail'].lower()

    async def test_valid_update_is_audited(self, visitor):
        registered = await register(visitor)

        response = await registered.put(visitor, registered.payload(description='Changed'))
        assert response.status_code == 202

        audits = (await visitor.get(f'/api/v1/networks/{registered.network_id}/audits')).json()
        assert [audit['action'] for audit in audits] == ['create', 'update']
        assert audits[1]['patch']

    async def test_blacklisted_network_cannot_be_updated(self, visitor, admin):
        registered = await register(visitor)
        await admin_action(admin, registered.network_id, 'blacklist')

        response = await registered.put(visitor, registered.payload(description='Changed'))

        assert response.status_code == 403
        assert 'blacklisted' in response.json()['detail'].lower()


class TestAdminLogin:
    @pytest.mark.parametrize('username,password', [
        ('test_admin', 'wrong password'),
        ('nobody_by_that_name', 'test_password'),
    ])
    async def test_bad_credentials_return_to_login(self, visitor, username, password):
        await visitor.get('/admin/login')

        response = await visitor.post(
            '/admin/login',
            data={
                'username': username,
                'password': password,
                'csrftoken': visitor.cookies.get('csrftoken'),
            },
            headers={'Referer': f'{BASE_URL}/admin/login'},
        )

        assert response.status_code == 303
        assert '/admin/login' in response.headers['Location']
        assert 'error=Invalid' in response.headers['Location']

        # Still anonymous
        assert (await visitor.get('/admin')).status_code == 303

    async def test_external_next_is_ignored(self, visitor):
        await visitor.get('/admin/login')

        response = await visitor.post(
            '/admin/login',
            data={
                'username': 'test_admin',
                'password': 'test_password',
                'next': 'https://evil.example/phish',
                'csrftoken': visitor.cookies.get('csrftoken'),
            },
            headers={'Referer': f'{BASE_URL}/admin/login'},
        )

        assert response.status_code == 303
        assert response.headers['Location'] == '/'

    async def test_login_page_redirects_when_signed_in(self, admin):
        response = await admin.get('/admin/login')

        assert response.status_code == 303
        assert response.headers['Location'] == '/'

    async def test_login_page_shows_error(self, visitor):
        response = await visitor.get('/admin/login', params={'error': 'Invalid username or password'})

        assert response.status_code == 200
        assert 'Invalid username or password' in response.text


class TestAdminActions:
    @pytest.mark.parametrize('action', ['approve', 'reject', 'blacklist'])
    async def test_actions_require_a_session(self, visitor, action):
        await visitor.get('/admin/login')

        response = await visitor.post(
            f'/admin/networks/{uuid.uuid4()}/{action}',
            data={'csrftoken': visitor.cookies.get('csrftoken')},
            headers={'Referer': f'{BASE_URL}/admin/login'},
        )

        assert response.status_code == 303
        assert '/admin/login' in response.headers['Location']

    @pytest.mark.parametrize('action', ['approve', 'reject', 'blacklist'])
    async def test_unknown_network_is_404(self, admin, action):
        response = await admin_action(admin, str(uuid.uuid4()), action)

        assert response.status_code == 404

    async def test_status_transitions_are_audited_once(self, visitor, admin):
        registered = await register(visitor)
        network_id = registered.network_id

        assert await status_of(visitor, network_id) == 'pending'

        for action, expected in [
            ('approve', 'active'),
            ('approve', 'active'),
            ('reject', 'rejected'),
            ('reject', 'rejected'),
            ('approve', 'active'),
            ('blacklist', 'blacklisted'),
            ('blacklist', 'blacklisted'),
        ]:
            response = await admin_action(admin, network_id, action)
            assert response.status_code == 303
            assert await status_of(visitor, network_id) == expected

        # Repeating an action changes nothing, so it must not add audit records
        audits = (await visitor.get(f'/api/v1/networks/{network_id}/audits')).json()
        assert [audit['action'] for audit in audits].count('create') == 1
        assert len(audits) == 1 + 4

    async def test_next_is_honoured_only_for_local_pages(self, visitor, admin):
        registered = await register(visitor)

        local = await admin_action(admin, registered.network_id, 'approve', next='/admin')
        assert local.headers['Location'].endswith('/admin')

        external = await admin_action(
            admin, registered.network_id, 'reject', next='https://evil.example/'
        )
        assert 'evil.example' not in external.headers['Location']
        assert external.headers['Location'].endswith(f'/networks/{registered.network_id}')

    async def test_logout_ends_the_session(self, app_manager):
        async with _client(app_manager) as client:
            await client.get('/admin/login')
            await client.post(
                '/admin/login',
                data={
                    'username': 'test_admin',
                    'password': 'test_password',
                    'csrftoken': client.cookies.get('csrftoken'),
                },
                headers={'Referer': f'{BASE_URL}/admin/login'},
            )
            assert (await client.get('/admin')).status_code == 200

            await client.get('/admin/logout')

            assert (await client.get('/admin')).status_code == 303


class TestPublicPages:
    async def test_visitors_only_see_active_networks(self, visitor, admin):
        pending = await register(visitor)
        active = await register(visitor)
        await admin_action(admin, active.network_id, 'approve')

        listing = await visitor.get('/networks', params={'q': 'Flow Network', 'limit': 100})
        assert active.network_id in listing.text
        assert pending.network_id not in listing.text

        # A status filter is ignored for visitors
        forced = await visitor.get('/networks', params={'status': 'pending', 'limit': 100})
        assert pending.network_id not in forced.text

        assert (await visitor.get(f'/networks/{pending.network_id}')).status_code == 404
        assert (await visitor.get(f'/networks/{active.network_id}')).status_code == 200

    async def test_admin_can_filter_by_status(self, visitor, admin):
        pending = await register(visitor)

        response = await admin.get(
            '/networks', params={'status': 'pending', 'q': pending.network_id, 'limit': 100}
        )
        assert response.status_code == 200
        assert pending.network_id in response.text

        detail = await admin.get(f'/networks/{pending.network_id}')
        assert detail.status_code == 200
        assert f'/admin/networks/{pending.network_id}/approve' in detail.text
        assert f'/admin/networks/{pending.network_id}/reject' in detail.text

    async def test_detail_actions_follow_the_status(self, visitor, admin):
        registered = await register(visitor)
        await admin_action(admin, registered.network_id, 'approve')

        detail = await admin.get(f'/networks/{registered.network_id}')

        # Active networks can be deactivated and banned, but not approved again
        assert f'/admin/networks/{registered.network_id}/approve' not in detail.text
        assert f'/admin/networks/{registered.network_id}/reject' in detail.text
        assert f'/admin/networks/{registered.network_id}/blacklist' in detail.text

    async def test_invalid_network_id_is_404(self, visitor):
        response = await visitor.get('/networks/not-a-uuid')

        assert response.status_code == 404
        assert 'Invalid network ID' in response.text

    async def test_unknown_network_page_is_404(self, visitor):
        response = await visitor.get(f'/networks/{uuid.uuid4()}')

        assert response.status_code == 404

    async def test_pagination_walks_every_page(self, visitor, admin):
        created = []
        for _ in range(3):
            registered = await register(visitor)
            await admin_action(admin, registered.network_id, 'approve')
            created.append(registered.network_id)

        seen = set()
        url = '/networks?limit=1'
        for _ in range(500):
            page = await visitor.get(url)
            assert page.status_code == 200
            seen.update(network_id for network_id in created if network_id in page.text)
            if len(seen) == len(created):
                break

            next_link = _link_with(page.text, 'cursor_id=', 'forward=true')
            if not next_link:
                break
            url = next_link

        assert seen == set(created)

    async def test_home_page_renders(self, visitor):
        response = await visitor.get('/')

        assert response.status_code == 200
        assert 'Decentralised Discovery Network Registry' in response.text

    async def test_unknown_page_renders_html_404(self, visitor):
        response = await visitor.get('/no/such/page')

        assert response.status_code == 404
        assert 'text/html' in response.headers['content-type']

    async def test_unknown_api_route_is_json_404(self, visitor):
        response = await visitor.get('/api/v1/no-such-route')

        assert response.status_code == 404
        assert 'application/json' in response.headers['content-type']


def _link_with(html: str, *needles: str) -> str | None:
    from html import unescape
    from bs4 import BeautifulSoup

    for anchor in BeautifulSoup(html, 'html.parser').find_all('a', href=True):
        href = unescape(anchor['href'])
        if all(needle in href for needle in needles):
            return href

    return None


class TestOperationalEndpoints:
    async def test_health(self, visitor):
        response = await visitor.get('/health')

        assert response.status_code == 200

    async def test_metrics_record_traffic(self, visitor):
        await visitor.get('/health')
        await visitor.get('/api/v1/challenge')

        response = await visitor.get('/metrics')

        assert response.status_code == 200
        assert 'http_requests_total' in response.text
        assert 'http_request_duration' in response.text

    async def test_metrics_endpoint_is_not_measured(self, visitor):
        await visitor.get('/metrics')
        response = await visitor.get('/metrics')

        assert 'endpoint="/metrics"' not in response.text


class TestCrossOrigin:
    async def test_api_answers_any_origin(self, visitor):
        response = await visitor.get('/api/v1/challenge', headers={'Origin': 'https://gateway.example'})

        assert response.status_code == 200
        assert response.headers['access-control-allow-origin'] == '*'

    async def test_ui_does_not_grant_unlisted_origins(self, visitor):
        response = await visitor.get('/networks', headers={'Origin': 'https://evil.example'})

        assert response.status_code == 200
        assert 'access-control-allow-origin' not in response.headers

    async def test_error_responses_from_the_api_carry_cors_headers(self, visitor):
        response = await visitor.get(
            f'/api/v1/networks/{uuid.uuid4()}', headers={'Origin': 'https://gateway.example'}
        )

        assert response.status_code == 404
        assert response.headers['access-control-allow-origin'] == '*'
