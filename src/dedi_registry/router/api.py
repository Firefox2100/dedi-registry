import json
import secrets
import hashlib
from uuid import UUID
import jsonpatch
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from pydantic import Field, ConfigDict
from fastapi import APIRouter, HTTPException, Query, Header, Depends, status

from dedi_registry.etc.consts import LOGGER, CONFIG
from dedi_registry.etc.enums import DatabaseConfigType, RecordAction, RecordStatus
from dedi_registry.etc.utils import validate_hash_challenge, reformat_pem
from dedi_registry.cache import Cache, get_active_cache
from dedi_registry.database import Database, get_active_db
from dedi_registry.model.base import JsonModel
from dedi_registry.model.network import Network, NetworkAuditRequestDetail, NetworkAudit
from .util import get_request_detail, serialise_network


api_router = APIRouter(
    prefix='/api',
    tags=['API'],
)


class ChallengeResponse(JsonModel):
    """
    A data transfer object for the response with a hash challenge.
    """

    model_config = ConfigDict(
        extra='forbid',
        serialize_by_alias=True,
    )

    nonce: str = Field(
        ...,
        description='A random nonce to be used in the challenge',
    )
    difficulty: int = Field(
        ...,
        description='The difficulty level of the challenge',
    )


@api_router.get('/v1/challenge', response_model=ChallengeResponse)
async def get_challenge_v1(cache: Cache = Depends(get_active_cache),
                           db: Database = Depends(get_active_db),
                           ):
    """
    Generate a Proof of Work challenge for request validation.

    This is to prevent spam and abuse of the unprotected endpoints by enforcing a
    CPU cost for each request.
    \f
    :param cache: The cache instance to store the challenge.
    :param db: The database instance to retrieve configuration settings.
    :return: The nonce and difficulty level for the challenge.
    """
    nonce = secrets.token_hex(16)
    security_config = await db.config.get_config(DatabaseConfigType.SECURITY)
    difficulty = security_config.base_difficulty + security_config.difficulty_shift

    LOGGER.debug(
        'Generating challenge with nonce: %s, difficulty: %d',
        nonce,
        difficulty
    )

    await cache.challenge.save_challenge(
        nonce=nonce,
        difficulty=difficulty
    )

    return ChallengeResponse(
        nonce=nonce,
        difficulty=difficulty
    )


@api_router.get('/v1/networks', response_model=list[Network])
async def list_networks_v1(db: Database = Depends(get_active_db),
                           network_status: RecordStatus | None = Query(
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
                           )):
    """
    List all registered networks in the system, optionally filtered by status.
    :param db: The database instance to retrieve networks from.
    :param network_status: Optional status to filter networks by.
    :param cursor_id: Optional ID of the last network from the previous page for pagination.
    :param limit: Maximum number of records to return. 0 for no limit.
    :param forward: Direction of pagination. True for forward, False for backward.
    :return: A list of networks matching the filter criteria.
    """
    networks = await db.networks.filter(
        status=network_status,
        cursor_id=cursor_id,
        limit=limit,
        forward=forward,
    )

    return networks[0]


@api_router.post('/v1/networks', response_model=Network, status_code=status.HTTP_201_CREATED)
async def register_network_v1(network: Network,
                              nonce: str = Query(..., description='The nonce received from the challenge endpoint'),
                              solution: str = Query(..., description='The challenge solution'),
                              sender_node: str = Header(
                                  ...,
                                  alias='Node-ID', description='The ID of the node sending the request'
                              ),
                              db: Database = Depends(get_active_db),
                              cache: Cache = Depends(get_active_cache),
                              request_detail: NetworkAuditRequestDetail = Depends(get_request_detail),
                              ):
    """
    Register a new network in the system.
    \f
    :param network: The network details to register.
    :param nonce: The nonce received from the challenge endpoint to validate the request.
    :param solution: The challenge solution to validate the request.
    :param sender_node: The ID of the node sending the request.
    :param db: The database instance to store the network.
    :param cache: The cache instance to retrieve the challenge for validation.
    :param request_detail: Details about the request for auditing purposes.
    :return: The registered network details.
    """
    challenge_difficulty = await cache.challenge.get_challenge(nonce)

    if not challenge_difficulty:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail='Invalid or expired challenge nonce.'
        )

    if not validate_hash_challenge(nonce, challenge_difficulty, solution):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail='Invalid challenge solution.'
        )

    existing_network = await db.networks.get(network.network_id)

    if existing_network:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f'Network with ID {network.network_id} already exists.'
        )

    node_found = False
    sender_uuid = UUID(sender_node)
    for node in network.nodes:
        if node.node_id == sender_uuid:
            node_found = True
            break

    if not node_found:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail='Sender node is not part of the network being registered.'
        )

    if CONFIG.auto_approve:
        network.status = RecordStatus.ACTIVE
    else:
        network.status = RecordStatus.PENDING

    await db.networks.save(network)

    json_dump = network.model_dump()
    json_str = network.model_dump_json()
    json_patch = jsonpatch.JsonPatch.from_diff({}, json_dump)

    audit_record = NetworkAudit(
        networkId=network.network_id,
        version=0,
        action=RecordAction.CREATE,
        actorNode=sender_node,
        patch=json_patch,
        hashAfter=f'sha256:{hashlib.sha256(json_str.encode()).hexdigest()}',
        requestDetail=request_detail
    )

    await db.audits.save(audit_record)

    LOGGER.info(
        'Registered new network with ID %s by node %s',
        network.network_id,
        sender_node
    )
    LOGGER.debug('Network details: %s', network.model_dump_json())

    return network


@api_router.get('/v1/networks/{network_id}', response_model=Network)
async def get_network_v1(network_id: str,
                         db: Database = Depends(get_active_db)
                         ):
    """
    Retrieve details of a specific network by its ID.
    :param network_id: The ID of the network to retrieve.
    :param db: The database instance to retrieve the network from.
    :return: The network details if found.
    """
    network = await db.networks.get(UUID(network_id))

    if not network:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f'Network with ID {network_id} not found.'
        )

    return network


@api_router.get('/v1/networks/{network_id}/audits', response_model=list[NetworkAudit])
async def get_network_audit_v1(network_id: str,
                               db: Database = Depends(get_active_db)
                               ):
    """
    Retrieve the audit trail for a specific network by its ID.
    :param network_id: The ID of the network to retrieve the audit trail for.
    :param db: The database instance to retrieve the audit records from.
    :return: A list of audit records for the specified network.
    """
    network = await db.networks.get(UUID(network_id))

    if not network:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f'Network with ID {network_id} not found.'
        )

    audits = await db.audits.get_network_audits(network_id=UUID(network_id))

    return audits


@api_router.put('/v1/networks/{network_id}', response_model=Network, status_code=status.HTTP_202_ACCEPTED)
async def update_network_v1(network_id: str,
                            network: Network,
                            sender_node: str = Header(
                                ...,
                                alias='Node-ID', description='The ID of the node sending the request'
                            ),
                            sender_signature: str = Header(
                                ...,
                                alias='Node-Signature',
                                description='The signature of the sender node over the network payload'
                            ),
                            db: Database = Depends(get_active_db),
                            request_detail: NetworkAuditRequestDetail = Depends(get_request_detail),
                            ):
    """
    Update an existing network in the system.
    :param network_id: The ID of the network to update.
    :param network: The updated network details.
    :param sender_node: The ID of the node sending the request.
    :param sender_signature: The signature of the sender node over the network payload.
    :param db: The database instance to update the network in.
    :param request_detail: Details about the request for auditing purposes.
    :return: The updated network details.
    """
    if str(network.network_id) != network_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail='Network ID in the path does not match the ID in the payload.'
        )

    existing_network = await db.networks.get(UUID(network_id))
    if not existing_network:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f'Network with ID {network_id} not found.'
        )

    node_found = False
    sender_uuid = UUID(sender_node)
    for node in network.nodes:
        if node.node_id == sender_uuid:
            node_found = True
            break

    if not node_found:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail='Sender node is not part of the network being updated.'
        )

    if existing_network.status == RecordStatus.BLACKLISTED:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail='Network is blacklisted and cannot be updated.'
        )

    network.public_key = reformat_pem(network.public_key)
    for node in network.nodes:
        node.public_key = reformat_pem(node.public_key)

    serialised_new_network = json.dumps(
        serialise_network(network),
        sort_keys=True,
        separators=(',', ':'),
        ensure_ascii=False,
    )
    management_key = serialization.load_pem_public_key(existing_network.public_key.encode())

    LOGGER.debug('New network serialised for signature verification: %s', serialised_new_network)
    LOGGER.debug('Used public key: %s', management_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode())
    LOGGER.debug('Sender signature: %s', sender_signature)

    try:
        management_key.verify(
            signature=bytes.fromhex(sender_signature),
            data=serialised_new_network.encode(),
            signature_algorithm=ec.ECDSA(hashes.SHA384())
        )
    except InvalidSignature as e:
        LOGGER.warning(
            'Signature verification failed for node %s on network %s update: %s',
            sender_node,
            network_id,
            str(e)
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail='Invalid signature from sender node.'
        )

    # Status is controlled by the registry admin, never by the submitting node
    network.status = existing_network.status

    json_dump = network.model_dump()
    json_str = network.model_dump_json()
    json_patch = jsonpatch.JsonPatch.from_diff(
        existing_network.model_dump(),
        json_dump
    )

    if not json_patch:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail='No changes detected in the network update.'
        )

    audits = await db.audits.get_network_audits(network_id=UUID(network_id))
    last_version = max((audit.version for audit in audits), default=0)
    old_json_str = existing_network.model_dump_json()
    old_hash = f'sha256:{hashlib.sha256(old_json_str.encode()).hexdigest()}'
    new_hash = f'sha256:{hashlib.sha256(json_str.encode()).hexdigest()}'
    audit_record = NetworkAudit(
        networkId=UUID(network_id),
        version=last_version + 1,
        action=RecordAction.UPDATE,
        actorNode=sender_node,
        patch=json_patch,
        hashBefore=old_hash,
        hashAfter=new_hash,
        requestDetail=request_detail
    )

    await db.networks.update(network)
    await db.audits.save(audit_record)

    LOGGER.info(
        'Updated network with ID %s by node %s',
        network_id,
        sender_node
    )
    LOGGER.debug('Network update details: %s', json_patch.to_string())

    return network
