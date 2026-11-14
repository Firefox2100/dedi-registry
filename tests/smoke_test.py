import os
import re
import httpx
import uuid
import json
import hashlib
import pytest
from httpx import ASGITransport
from bs4 import BeautifulSoup, SoupStrainer
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from asgi_lifespan import LifespanManager
from typer.testing import CliRunner

from dedi_registry.app import create_app
from dedi_registry.cli.cli import create_cli


def reformat_pem(pem: str) -> str:
    """
    Reformat a PEM string to ensure proper line breaks.
    :param pem: The PEM string to reformat.
    :return: A reformatted PEM string. Line break every 64 characters within the body.
    """
    pem = pem.strip()

    # Remove existing line breaks
    pem = (pem.replace('\n', '').replace('\r', '')
           .replace('\\n', '').replace('\\r', ''))

    # Split the PEM into header, body, and footer
    header = '-----BEGIN PUBLIC KEY-----'
    footer = '-----END PUBLIC KEY-----'
    if not (pem.startswith(header) and pem.endswith(footer)):
        raise ValueError('Invalid PEM format')

    body = pem[len(header):-len(footer)].strip()

    # Insert line breaks every 64 characters in the body
    body_lines = [body[i:i+64] for i in range(0, len(body), 64)]
    reformatted_body = '\n'.join(body_lines)

    # Reconstruct the PEM with proper formatting
    reformatted_pem = f'{header}\n{reformatted_body}\n{footer}'
    return reformatted_pem


NETWORK_ID = str(uuid.uuid4())
NETWORK_NAME = f'Test Network {NETWORK_ID}'
NETWORK_DESCRIPTION = 'This is a test network created during smoke testing.'
NETWORK_PRIVATE_KEY = ec.generate_private_key(
    curve=ec.SECP384R1(),
)
NETWORK_PUBLIC_PEM = reformat_pem(NETWORK_PRIVATE_KEY.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
).decode())
NODE_ID_1 = str(uuid.uuid4())
NODE_NAME_1 = f'Test Node 1 {NODE_ID_1}'
NODE_URL_1 = 'http://localhost:5877'
NODE_DESCRIPTION_1 = f'This is a test node created during smoke testing.'
NODE_PRIVATE_KEY_1 = ec.generate_private_key(
    curve=ec.SECP384R1(),
)
NODE_PUBLIC_PEM_1 = reformat_pem(NODE_PRIVATE_KEY_1.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
).decode())
NEW_USER_ID = str(uuid.uuid4())

@pytest.fixture(scope='session')
def base_url():
    return os.getenv('TEST_BASE_URL', 'http://localhost:5876')


@pytest.fixture(scope='session')
def admin_credentials():
    return {
        'username': os.getenv('TEST_ADMIN_USERNAME', 'test_admin'),
        'password': os.getenv('TEST_ADMIN_PASSWORD', 'test_password'),
    }


@pytest.fixture(scope='session')
async def client(base_url, app_manager):
    transport = ASGITransport(app=app_manager.app)
    async with httpx.AsyncClient(transport=transport, base_url=base_url) as client:
        client.headers.update({
            'User-Agent': 'DediRegistrySmokeTest/1.0',
        })
        yield client


def solve_challenge(nonce: str, difficulty: int) -> int:
    """
    Solve a proof of work challenge .
    :param nonce: The nonce to use for the proof of work challenge.
    :param difficulty: How many leading zeros the hash should have.
    :return: The valid nonce that solves the challenge.
    """
    if not isinstance(nonce, str) or not isinstance(difficulty, int):
        raise TypeError('Expected nonce: str and difficulty: int')
    if difficulty < 1 or difficulty > 256:
        raise ValueError('Difficulty must be between 1 and 256')

    target_prefix = '0' * difficulty

    for counter in range(1 << 64):  # covers entire 64-bit unsigned range
        data = f'{nonce}{counter}'.encode()
        digest = hashlib.sha256(data).hexdigest()
        bin_hash = bin(int(digest, 16))[2:].zfill(256)

        if bin_hash.startswith(target_prefix):
            return counter

    raise RuntimeError('No valid nonce found within 64-bit search space')


async def test_homepage_accessible(client):
    response = await client.get('/')

    assert response.status_code == 200
    assert 'text/html' in response.headers['Content-Type']


async def test_networks_page_accessible(base_url, client):
    response = await client.get('/networks')

    assert response.status_code == 200
    assert 'text/html' in response.headers['Content-Type']


async def test_static_files_have_content(client):
    for path in ('/static/css/custom.css', '/static/js/app.js'):
        response = await client.get(path)

        assert response.status_code == 200
        assert len(response.content) > 0
        assert len(response.content) == int(response.headers['Content-Length'])


async def test_get_challenge(client):
    response = await client.get('/api/v1/challenge')

    assert response.status_code == 200
    data = response.json()

    assert 'nonce' in data
    assert 'difficulty' in data

    # Try to solve the challenge
    nonce = data['nonce']
    difficulty = data['difficulty']
    solution = solve_challenge(nonce, difficulty)

    assert isinstance(solution, int)


async def test_register_network(client):
    # First, get a challenge
    challenge_response = await client.get('/api/v1/challenge')
    assert challenge_response.status_code == 200
    challenge_data = challenge_response.json()

    nonce = challenge_data['nonce']
    difficulty = challenge_data['difficulty']
    solution = solve_challenge(nonce, difficulty)

    # Prepare the data payload
    network_data = {
        'networkId': NETWORK_ID,
        'networkName': NETWORK_NAME,
        'description': NETWORK_DESCRIPTION,
        'publicKey': NETWORK_PUBLIC_PEM,
        'nodes': [{
            'nodeId': NODE_ID_1,
            'nodeName': NODE_NAME_1,
            'url': NODE_URL_1,
            'description': NODE_DESCRIPTION_1,
            'publicKey': NODE_PUBLIC_PEM_1,
        }]
    }

    creation_response = await client.post(
        url='/api/v1/networks',
        json=network_data,
        headers={
            'Node-ID': NODE_ID_1,
        },
        params={
            'nonce': nonce,
            'solution': str(solution),
        }
    )

    assert creation_response.status_code == 201
    creation_result = creation_response.json()
    assert creation_result['networkId'] == NETWORK_ID
    assert creation_result['status'] == 'pending'
    assert creation_result['networkName'] == NETWORK_NAME
    assert creation_result['description'] == NETWORK_DESCRIPTION
    assert len(creation_result['nodes']) == 1
    assert creation_result['nodes'][0]['nodeId'] == NODE_ID_1
    assert creation_result['nodes'][0]['nodeName'] == NODE_NAME_1
    assert creation_result['nodes'][0]['url'] == NODE_URL_1
    assert creation_result['nodes'][0]['description'] == NODE_DESCRIPTION_1


async def test_list_networks(client):
    response = await client.get('/api/v1/networks')

    assert response.status_code == 200
    data = response.json()

    assert isinstance(data, list)
    assert len(data) == 1
    network_data = data[0]
    assert network_data['networkId'] == NETWORK_ID
    assert network_data['networkName'] == NETWORK_NAME
    assert network_data['description'] == NETWORK_DESCRIPTION
    assert len(network_data['nodes']) == 1
    assert network_data['nodes'][0]['nodeId'] == NODE_ID_1
    assert network_data['nodes'][0]['nodeName'] == NODE_NAME_1
    assert network_data['nodes'][0]['url'] == NODE_URL_1
    assert network_data['nodes'][0]['description'] == NODE_DESCRIPTION_1


async def test_get_network_details(client):
    response = await client.get(f'/api/v1/networks/{NETWORK_ID}')

    assert response.status_code == 200
    network_data = response.json()
    assert network_data['networkId'] == NETWORK_ID
    assert network_data['networkName'] == NETWORK_NAME
    assert network_data['description'] == NETWORK_DESCRIPTION
    assert len(network_data['nodes']) == 1
    assert network_data['nodes'][0]['nodeId'] == NODE_ID_1
    assert network_data['nodes'][0]['nodeName'] == NODE_NAME_1
    assert network_data['nodes'][0]['url'] == NODE_URL_1
    assert network_data['nodes'][0]['description'] == NODE_DESCRIPTION_1


async def test_get_network_audits(client):
    response = await client.get(f'/api/v1/networks/{NETWORK_ID}/audits')

    assert response.status_code == 200
    audits = response.json()
    assert isinstance(audits, list)
    assert len(audits) == 1  # Creation event

    creation_audit = audits[0]
    assert creation_audit['networkId'] == NETWORK_ID
    assert creation_audit['action'] == 'create'
    assert creation_audit['version'] == 0
    assert creation_audit['actorNode'] == NODE_ID_1
    assert 'timestamp' in creation_audit
    assert isinstance(creation_audit['patch'], list)
    assert len(creation_audit['patch']) == 6 # 6 fields in the creation
    assert 'hashAfter' in creation_audit

    request_details = creation_audit['requestDetail']
    assert request_details['userAgent'] == 'DediRegistrySmokeTest/1.0'


async def test_update_network(client):
    updated_data = {
        'description': 'This network is now updated.',
        'networkId': NETWORK_ID,
        'networkName': f'Updated Test Network {NETWORK_ID}',
        'nodes': [{
            'nodeId': NODE_ID_1,
            'nodeName': NODE_NAME_1,
            'url': NODE_URL_1,
            'description': 'This node is now updated.',
            'publicKey': NODE_PUBLIC_PEM_1,
        }],
        'publicKey': NETWORK_PUBLIC_PEM,
    }

    serialised_str = json.dumps(updated_data, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
    signature = NETWORK_PRIVATE_KEY.sign(
        data=serialised_str.encode(),
        signature_algorithm=ec.ECDSA(hashes.SHA384()),
    ).hex()

    response = await client.put(
        url=f'/api/v1/networks/{NETWORK_ID}',
        json=updated_data,
        headers={
            'Node-ID': NODE_ID_1,
            'Node-Signature': signature,
        },
    )

    assert response.status_code == 202
    update_result = response.json()
    assert update_result['networkId'] == NETWORK_ID
    assert update_result['status'] == 'pending'
    assert update_result['networkName'] == updated_data['networkName']
    assert update_result['description'] == updated_data['description']
    assert len(update_result['nodes']) == 1
    assert update_result['nodes'][0]['nodeId'] == NODE_ID_1
    assert update_result['nodes'][0]['description'] == 'This node is now updated.'

    # The update must actually be persisted, not just echoed back
    stored_response = await client.get(f'/api/v1/networks/{NETWORK_ID}')
    assert stored_response.status_code == 200
    stored = stored_response.json()
    assert stored['networkName'] == updated_data['networkName']
    assert stored['description'] == updated_data['description']
    assert stored['status'] == 'pending'
    assert stored['nodes'][0]['description'] == 'This node is now updated.'

    audit_response = await client.get(f'/api/v1/networks/{NETWORK_ID}/audits')
    assert audit_response.status_code == 200
    audits = audit_response.json()
    assert len(audits) == 2  # Creation + Update
    update_audit = audits[1]
    assert update_audit['action'] == 'update'
    assert update_audit['version'] == 1
    assert update_audit['actorNode'] == NODE_ID_1
    assert 'timestamp' in update_audit
    assert isinstance(update_audit['patch'], list)
    assert len(update_audit['patch']) == 3
    assert 'hashBefore' in update_audit
    assert 'hashAfter' in update_audit
    request_details = update_audit['requestDetail']
    assert request_details['userAgent'] == 'DediRegistrySmokeTest/1.0'
    assert audits[0]['hashAfter'] == update_audit['hashBefore']


async def test_node_joins_and_leaves_network(client):
    node_id_2 = str(uuid.uuid4())
    node_1 = {
        'nodeId': NODE_ID_1,
        'nodeName': NODE_NAME_1,
        'url': NODE_URL_1,
        'description': 'This node is now updated.',
        'publicKey': NODE_PUBLIC_PEM_1,
    }
    node_2 = {
        'nodeId': node_id_2,
        'nodeName': 'Joining Node',
        'url': 'http://localhost:5878',
        'description': '',
        'publicKey': NODE_PUBLIC_PEM_1,
    }

    async def put_nodes(nodes: list[dict]):
        data = {
            'description': 'This network is now updated.',
            'networkId': NETWORK_ID,
            'networkName': f'Updated Test Network {NETWORK_ID}',
            # The signed form lists nodes sorted by ID, whatever order they are sent in
            'nodes': sorted(nodes, key=lambda node: node['nodeId']),
            'publicKey': NETWORK_PUBLIC_PEM,
        }
        serialised = json.dumps(data, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
        signature = NETWORK_PRIVATE_KEY.sign(
            data=serialised.encode(),
            signature_algorithm=ec.ECDSA(hashes.SHA384()),
        ).hex()

        return await client.put(
            url=f'/api/v1/networks/{NETWORK_ID}',
            json=data,
            headers={'Node-ID': NODE_ID_1, 'Node-Signature': signature},
        )

    async def stored_node_ids() -> set[str]:
        stored = (await client.get(f'/api/v1/networks/{NETWORK_ID}')).json()
        return {node['nodeId'] for node in stored['nodes']}

    assert (await put_nodes([node_1, node_2])).status_code == 202
    assert await stored_node_ids() == {NODE_ID_1, node_id_2}

    assert (await put_nodes([node_1])).status_code == 202
    assert await stored_node_ids() == {NODE_ID_1}


async def test_pending_network_hidden_from_visitors(client):
    listing = await client.get('/networks')
    assert listing.status_code == 200
    assert NETWORK_ID not in listing.text

    detail = await client.get(f'/networks/{NETWORK_ID}')
    assert detail.status_code == 404

    # Asking for a status does not widen what a visitor can see
    filtered = await client.get('/networks', params={'status': 'pending'})
    assert filtered.status_code == 200
    assert NETWORK_ID not in filtered.text


async def test_admin_login(client, admin_credentials):
    login_page_response = await client.get('/admin/login')

    assert login_page_response.status_code == 200
    csrf_token = client.cookies.get('csrftoken')
    assert csrf_token is not None

    form_data = {
        'username': admin_credentials['username'],
        'password': admin_credentials['password'],
        'csrftoken': csrf_token,
        'next': '/',
    }

    login_response = await client.post(
        url='/admin/login',
        data=form_data,
        headers={
            'Referer': f'{client.base_url}/admin/login',
            'Content-Type': 'application/x-www-form-urlencoded',
        }
    )

    assert login_response.status_code == 303
    assert login_response.headers['Location'] == '/'

    homepage_response = await client.get('/')
    homepage_text = homepage_response.text
    nav_only = SoupStrainer('nav')
    soup = BeautifulSoup(homepage_text, 'html.parser', parse_only=nav_only)

    links = []
    for a in soup.select('a.nav-link'):
        text = ' '.join(a.get_text(strip=True).split())
        href = a.get('href')
        links.append((text, href))

    texts = [t for t, _ in links]

    # Should have a logout button
    assert any(re.match(r'Logout \(.*\)', t) for t in texts)


async def test_admin_dashboard_lists_pending(client):
    response = await client.get('/admin')

    assert response.status_code == 200
    soup = BeautifulSoup(response.text, 'html.parser')
    assert NETWORK_ID in response.text
    assert soup.select_one(f'form[action$="/admin/networks/{NETWORK_ID}/approve"]') is not None

    # Administrators can see and filter by every status
    pending = await client.get('/networks', params={'status': 'pending'})
    assert pending.status_code == 200
    assert NETWORK_ID in pending.text


async def test_admin_approve_network(client):
    # The client should already be logged in from the previous test
    network_details_response = await client.get(f'/networks/{NETWORK_ID}')

    assert network_details_response.status_code == 200
    csrf_token = client.cookies.get('csrftoken')
    assert csrf_token is not None

    form_data = {
        'csrftoken': csrf_token,
    }

    approve_response = await client.post(
        url=f'/admin/networks/{NETWORK_ID}/approve',
        data=form_data,
        headers={
            'Referer': f'{client.base_url}/networks/{NETWORK_ID}',
            'Content-Type': 'application/x-www-form-urlencoded',
        }
    )

    assert approve_response.status_code == 303
    assert approve_response.headers['Location'] == f'{client.base_url}/networks/{NETWORK_ID}'


async def test_logout(client, base_url):
    logout_response = await client.get('/admin/logout')

    assert logout_response.status_code == 303
    assert logout_response.headers['Location'] == f'{base_url}/admin/login'


async def test_active_network_visible_to_visitors(client):
    # The client has logged out by now, so these requests are anonymous
    dashboard = await client.get('/admin')
    assert dashboard.status_code == 303
    assert dashboard.headers['Location'].startswith(f'{client.base_url}/admin/login')

    listing = await client.get('/networks')
    assert listing.status_code == 200
    assert NETWORK_ID in listing.text

    # Search matches part of the name, ignoring case
    found = await client.get('/networks', params={'q': 'UPDATED TEST'})
    assert found.status_code == 200
    assert NETWORK_ID in found.text

    missing = await client.get('/networks', params={'q': 'no such network'})
    assert missing.status_code == 200
    assert NETWORK_ID not in missing.text

    # Search text is literal, never a pattern
    pattern = await client.get('/networks', params={'q': '.*'})
    assert pattern.status_code == 200
    assert NETWORK_ID not in pattern.text

    detail = await client.get(f'/networks/{NETWORK_ID}')
    assert detail.status_code == 200
    assert 'Audit trail' in detail.text


async def test_create_user_with_cli(admin_credentials):
    app = create_cli()
    runner = CliRunner()

    result = runner.invoke(app, ['user', 'create', f'smoke_test_{NEW_USER_ID}', '--password', 'TestPassword123!'])
    assert result.exit_code == 0

    result = runner.invoke(app, ['user', 'list'])
    assert result.exit_code == 0


async def test_login_with_new_user(client):
    login_page_response = await client.get('/admin/login')

    assert login_page_response.status_code == 200
    csrf_token = client.cookies.get('csrftoken')
    assert csrf_token is not None

    form_data = {
        'username': f'smoke_test_{NEW_USER_ID}',
        'password': 'TestPassword123!',
        'csrftoken': csrf_token,
        'next': '/',
    }

    login_response = await client.post(
        url='/admin/login',
        data=form_data,
        headers={
            'Referer': f'{client.base_url}/admin/login',
            'Content-Type': 'application/x-www-form-urlencoded',
        }
    )

    assert login_response.status_code == 303
    assert login_response.headers['Location'] == '/'

    homepage_response = await client.get('/')
    homepage_text = homepage_response.text
    nav_only = SoupStrainer('nav')
    soup = BeautifulSoup(homepage_text, 'html.parser', parse_only=nav_only)

    links = []
    for a in soup.select('a.nav-link'):
        text = ' '.join(a.get_text(strip=True).split())
        href = a.get('href')
        links.append((text, href))

    texts = [t for t, _ in links]

    # Should have a logout button
    assert any(re.match(r'Logout \(.*\)', t) for t in texts)


async def test_get_metrics(client):
    response = await client.get('/metrics')

    assert response.status_code == 200
    assert 'text/plain' in response.headers['Content-Type']
    assert 'http_requests_total' in response.text
