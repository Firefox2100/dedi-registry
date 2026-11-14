from urllib.parse import urlencode
from uuid import UUID
from fastapi import APIRouter, Query, Depends, Request
from fastapi.responses import HTMLResponse

from dedi_registry.etc.enums import RecordStatus
from dedi_registry.database import Database, get_active_db
from .util import TEMPLATES, build_nav_links


ui_router = APIRouter(
    tags=['UI'],
)

HOME_NETWORK_LIMIT = 8
STATUS_LABELS = {
    RecordStatus.ACTIVE: 'Active',
    RecordStatus.PENDING: 'Pending',
    RecordStatus.REJECTED: 'Rejected',
    RecordStatus.BLACKLISTED: 'Banned',
}


@ui_router.get('/', response_class=HTMLResponse)
async def get_home_page(request: Request,
                        db: Database = Depends(get_active_db),
                        ):
    """
    Serve the home page of the Decentralised Discovery Network Registry.
    \f
    :param request: Request object.
    :param db: Database instance.
    :return: An HTML response with the home page content.
    """
    network_count = await db.networks.count(RecordStatus.ACTIVE)
    node_count = await db.networks.count_nodes(RecordStatus.ACTIVE)
    networks, _, _ = await db.networks.filter(
        status=RecordStatus.ACTIVE,
        limit=HOME_NETWORK_LIMIT,
    )
    nav_links = await build_nav_links(request, db)

    return TEMPLATES.TemplateResponse(
        request,
        'home.html',
        {
            'page_title': 'Home | Decentralised Discovery Network Registry',
            'network_count': network_count,
            'node_count': node_count,
            'networks': networks,
            'has_more': network_count > len(networks),
            'nav_links': nav_links,
        }
    )


@ui_router.get('/networks', response_class=HTMLResponse)
async def display_networks(request: Request,
                           network_status: RecordStatus = Query(
                               None,
                               description='Filter networks by their status',
                               alias='status',
                           ),
                           cursor_id: str | None = Query(
                               None,
                               description='The ID of the last network from the previous page for pagination'
                           ),
                           limit: int = Query(
                               10,
                               ge=0,
                               le=100,
                               description='The maximum number of records to return. 0 for no limit.'
                           ),
                           forward: bool = Query(
                               True,
                               description='Direction of pagination. True for forward, False for backward.'
                           ),
                           search: str | None = Query(
                               None,
                               alias='q',
                               max_length=100,
                               description='Text the network name must contain',
                           ),
                           db: Database = Depends(get_active_db),
                           ):
    """
    Display a list of networks with optional filtering and pagination.

    Visitors only see active networks. Signed-in administrators see every status
    and may filter by it.
    \f
    :param request: Request object.
    :param network_status: Optional status to filter networks by. Ignored for visitors.
    :param search: Optional text the network name must contain.
    :param cursor_id: Optional ID of the last network from the previous page for pagination.
    :param limit: Maximum number of records to return. 0 for no limit.
    :param forward: Direction of pagination. True for forward, False for backward.
    :param db: Database instance.
    :return: An HTML response with the list of networks.
    """
    is_admin = bool(request.session.get('username'))
    if not is_admin:
        network_status = RecordStatus.ACTIVE

    search = (search or '').strip() or None

    networks, first_cursor_id, last_cursor_id = await db.networks.filter(
        status=network_status,
        cursor_id=cursor_id,
        limit=limit,
        forward=forward,
        name=search,
    )

    show_prev = cursor_id is not None
    show_next = last_cursor_id is not None

    def build_url(new_cursor_id: str | None,
                  new_forward: bool,
                  status_value: str | None = None,
                  ) -> str:
        params = {
            'cursor_id': new_cursor_id,
            'limit': limit,
            'forward': str(new_forward).lower(),
            'status': status_value,
            'q': search,
        }

        return '/networks?' + urlencode({k: v for k, v in params.items() if v is not None})

    current_status = network_status.value if network_status else None
    prev_url = build_url(first_cursor_id, False, current_status) if show_prev else None
    next_url = build_url(last_cursor_id, True, current_status) if show_next else None

    status_filters = []
    if is_admin:
        for option in (None, *RecordStatus):
            value = option.value if option else None
            query = {'status': value, 'q': search}
            status_filters.append({
                'label': STATUS_LABELS[option] if option else 'All',
                'count': await db.networks.count(option),
                'url': '/networks?' + urlencode({k: v for k, v in query.items() if v is not None}),
                'active': value == current_status,
            })

    return TEMPLATES.TemplateResponse(
        request,
        'networks.html',
        {
            'page_title': 'Networks | Decentralised Discovery Network Registry',
            'networks': networks,
            'network_status': current_status,
            'query': search,
            'is_admin': is_admin,
            'status_filters': status_filters,
            'prev_url': prev_url,
            'next_url': next_url,
            'nav_links': await build_nav_links(request, db),
        }
    )


@ui_router.get('/networks/{network_id}', response_class=HTMLResponse)
async def display_network_detail(request: Request,
                                 network_id: str,
                                 db: Database = Depends(get_active_db),
                                 ):
    """
    Display detailed information about a specific network.
    \f
    :param request: Request object.
    :param network_id: The ID of the network to display.
    :param db: Database instance.
    :return: An HTML response with the network details.
    """
    try:
        network_uuid = UUID(network_id, version=4)
    except ValueError:
        return TEMPLATES.TemplateResponse(
            request,
            '404.html',
            {
                'page_title': 'Network Not Found | Decentralised Discovery Network Registry',
                'detail': f'Invalid network ID format: {network_id}',
                'return_url': request.url_for('display_networks'),
                'return_label': 'Back to Networks',
                'nav_links': await build_nav_links(request, db),
            },
            status_code=404,
        )
    network = await db.networks.get(network_uuid)
    is_admin = bool(request.session.get('username'))

    # Networks that are not active are only visible to administrators; to anyone
    # else they look the same as a network that does not exist
    if not network or (network.status != RecordStatus.ACTIVE and not is_admin):
        return TEMPLATES.TemplateResponse(
            request,
            '404.html',
            {
                'page_title': 'Network Not Found | Decentralised Discovery Network Registry',
                'detail': f'Network with ID {network_id} not found.',
                'return_url': request.url_for('display_networks'),
                'return_label': 'Back to Networks',
                'nav_links': await build_nav_links(request, db),
            },
            status_code=404,
        )

    network_audits = await db.audits.get_network_audits(network_uuid)

    audit_view = []
    for audit in network_audits or []:
        if audit.actor_node != 'Administrator':
            actor_node = next(
                (node for node in network.nodes or [] if str(node.node_id) == audit.actor_node),
                None
            )
            actor_name = actor_node.node_name if actor_node else audit.actor_node
        else:
            actor_name = audit.actor_node

        audit_view.append({
            'version': audit.version,
            'action': audit.action.value,
            'actor': actor_name,
            'timestamp': audit.timestamp.isoformat(),
            'hash_before': audit.hash_before,
            'hash_after': audit.hash_after,
            'request_detail': {
                'ip_address': audit.request_detail.ip_address,
                'user_agent': audit.request_detail.user_agent,
            },
            'patch': audit.patch or [],
        })

    actions = []
    if is_admin:
        if network.status == RecordStatus.PENDING:
            actions.append({
                'label': 'Accept',
                'tone': 'primary',
                'post_url': request.url_for('approve_network_registration', network_id=network_id),
            })
            actions.append({
                'label': 'Reject',
                'tone': 'quiet',
                'confirm': 'The network is marked rejected and stays out of the public listing.',
                'post_url': request.url_for('reject_network_registration', network_id=network_id),
            })

        if network.status == RecordStatus.ACTIVE:
            actions.append({
                'label': 'Deactivate',
                'tone': 'quiet',
                'confirm': 'The network is removed from the public listing.',
                'post_url': request.url_for('reject_network_registration', network_id=network_id),
            })

        actions.append({
            'label': 'Ban',
            'tone': 'danger',
            'confirm': 'The network is blacklisted, and its IP address, domain and user agent '
                       'are blocked from registering again.',
            'post_url': request.url_for('blacklist_network', network_id=network_id),
        })

    return TEMPLATES.TemplateResponse(
        request,
        'network_detail.html',
        {
            'page_title': f'Network {network.network_name} | Decentralised Discovery Network Registry',
            'network': {
                'network_id': str(network.network_id),
                'network_name': network.network_name,
                'description': network.description,
                'status': network.status.value,
                'public_key': network.public_key,
                'nodes': [
                    {
                        'url': node.url,
                        'name': node.node_name,
                        'description': node.description,
                        'public_key': node.public_key,
                    } for node in network.nodes or []
                ]
            },
            'network_status': network.status.value,
            'is_admin': is_admin,
            'audits': audit_view,
            'nav_links': await build_nav_links(request, db),
            'actions': actions,
        }
    )
