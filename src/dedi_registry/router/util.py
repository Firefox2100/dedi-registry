import re
import posixpath
from datetime import datetime, timezone
import importlib.resources as pkg_resources
from urllib.parse import urlsplit, urlunsplit
from fastapi import Request
from fastapi.templating import Jinja2Templates

from dedi_registry import __version__
from dedi_registry.database import Database
from dedi_registry.model.network import Network, NetworkAuditRequestDetail


_allowed_redirect_destinations = [
    '/',
    '/networks',
    '/admin',
    '/admin/login',
]
_allowed_redirect_regex = [
    re.compile(
        r'^/networks/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'
    )
]


def get_request_detail(request: Request) -> NetworkAuditRequestDetail:
    """
    Extract request details such as IP address and User-Agent from the incoming request.
    :param request: The incoming HTTP request.
    :return: An instance of NetworkAuditRequestDetail containing the extracted details.
    """
    ip_address = request.client.host or 'unknown'
    user_agent = request.headers.get('user-agent', 'unknown')[:512]

    return NetworkAuditRequestDetail(
        ipAddress=ip_address,
        userAgent=user_agent
    )


async def build_nav_links(request: Request, db: Database) -> list[dict]:
    """
    Build the navigation links in the nav bar for the UI.
    :return: A list of navigation link dictionaries.
    """
    path = request.url.path
    username = request.session.get('username')

    if username:
        user = await db.users.get(username)

        if not user:
            username = None
            request.session['username'] = None

    # The brand in the header links to the home page, so it has no entry here
    nav_links = [
        {
            'label': 'Networks',
            'url': request.url_for('display_networks'),
            'active': path.startswith('/networks'),
        },
        {
            'label': 'API',
            'url': '/docs',
            'active': False,
        },
    ]

    if username:
        nav_links.append({
            'label': 'Dashboard',
            'url': request.url_for('get_admin_dashboard'),
            'active': path.startswith('/admin')
        })
        nav_links.append({
            'label': f'Logout ({username})',
            'url': request.url_for('admin_logout'),
            'active': False
        })
    else:
        nav_links.append({
            'label': 'Login',
            'url': str(request.url_for('get_admin_login_page')) + f'?next={path}',
        })

    return nav_links


def serialise_network(network: Network) -> dict:
    """
    Deterministically serialise a network to a dictionary for hashing.

    Applied transformations:
    - Remove fields that are not part of the submission (status, etc.)
    - Remove empty fields and null values
    - Sort all fields alphabetically
    - Sort nodes alphabetically by node ID
    :param network: The network to serialise.
    :return: A dictionary representation of the network.
    """
    payload = network.model_dump()

    # Remove non-submission fields
    for field in ['status', 'version', 'createdAt', 'updatedAt']:
        payload.pop(field, None)

    # Remove empty fields and null values
    payload = {k: v for k, v in payload.items() if v not in (None, [], {})}

    # Sort nodes by node ID
    if 'nodes' in payload:
        payload['nodes'] = sorted(payload['nodes'], key=lambda n: str(n['nodeId']))

    # Sort all fields alphabetically
    payload = dict(sorted(payload.items()))

    return payload


def get_templates() -> Jinja2Templates:
    """
    Get the Jinja2 templates instance for rendering HTML templates.
    :return:
    """
    template_path = pkg_resources.files('dedi_registry.data') / 'templates'
    templates = Jinja2Templates(directory=str(template_path))
    templates.env.globals['app_version'] = __version__
    templates.env.globals['current_year'] = lambda: datetime.now(tz=timezone.utc).year

    return templates


TEMPLATES = get_templates()


def sanitise_next_url(next_url: str | None = None,
                      default: str = '/',
                      ) -> str:
    """
    Sanitise the next URL to prevent open redirect vulnerabilities.
    :param next_url: The next URL to sanitise.
    :param default: The default URL to use if the next URL is not valid.
    :return: The sanitised next URL.
    """
    if not next_url:
        return default

    parts = urlsplit(next_url)

    if parts.scheme or parts.netloc:
        return default

    normalised = posixpath.normpath(parts.path or '/')
    if not normalised.startswith('/'):
        normalised = '/' + normalised

    while normalised.startswith('//'):
        normalised = normalised[1:]

    def _is_allowed(path: str) -> bool:
        if path in _allowed_redirect_destinations:
            return True

        return any(regex.match(path) for regex in _allowed_redirect_regex)

    if not _is_allowed(normalised):
        return default

    # Shouldn't have fragments for now. Change if needed.
    clean = urlunsplit(('', '', normalised, parts.query, ''))

    return clean
