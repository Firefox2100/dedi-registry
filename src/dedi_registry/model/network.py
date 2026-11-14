from abc import ABC, abstractmethod
from datetime import datetime, timezone
from uuid import UUID
from typing import Optional
from pydantic import Field, ConfigDict

from dedi_registry.etc.enums import RecordAction, RecordStatus
from .base import JsonModel
from .node import Node
from .json_patch import JsonPatchEntry


class Network(JsonModel):
    """
    A network with nodes to share data among each other.
    """

    model_config = ConfigDict(
        extra='forbid',
        serialize_by_alias=True,
    )

    network_id: UUID = Field(
        ...,
        alias='networkId',
        description='The unique ID of the network. Should be UUID4 format.'
    )
    status: RecordStatus = Field(
        default=RecordStatus.PENDING,
        description='The status of the network record'
    )
    network_name: str = Field(
        ...,
        alias='networkName',
        description='The name of the network'
    )
    description: str = Field(
        default='',
        description='A description of the network'
    )
    nodes: list[Node] = Field(
        default_factory=list,
        description='The nodes in the network'
    )
    public_key: str = Field(
        ...,
        alias='publicKey',
        description='The public key of the network for authorised update of records, in PEM format'
    )


class NetworkAuditRequestDetail(JsonModel):
    """
    Audit detail for a network record update request.
    """

    model_config = ConfigDict(
        extra='forbid',
        serialize_by_alias=True,
    )

    ip_address: str = Field(
        ...,
        alias='ipAddress',
        description='The IP address from which the request was made'
    )
    user_agent: str = Field(
        ...,
        alias='userAgent',
        description='The user agent of the client making the request'
    )


class NetworkAudit(JsonModel):
    """
    Audit record for a network.
    """

    model_config = ConfigDict(
        extra='forbid',
        serialize_by_alias=True,
    )

    network_id: UUID = Field(
        ...,
        alias='networkId',
        description='The unique ID of the network. Should be UUID4 format.'
    )
    version: int = Field(
        ...,
        description='The version number of the audit record'
    )
    action: RecordAction = Field(
        ...,
        description='The action performed on the network record'
    )
    actor_node: str = Field(
        ...,
        alias='actorNode',
        description='The ID of the node that performed the action'
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(tz=timezone.utc),
        description='The timestamp when the action was performed'
    )
    patch: list[JsonPatchEntry] = Field(
        default_factory=list,
        description='The JSON Patch entries representing the changes made'
    )
    hash_before: Optional[str] = Field(
        default=None,
        alias='hashBefore',
        description='The hash of the network record before the change, if applicable'
    )
    hash_after: str = Field(
        ...,
        alias='hashAfter',
        description='The hash of the network record after the change'
    )
    request_detail: NetworkAuditRequestDetail = Field(
        ...,
        alias='requestDetail',
        description='Details about the request that triggered the action'
    )


class NetworkRepository(ABC):
    """
    An interface for database operations related to Network entities.
    """

    @abstractmethod
    async def get(self, network_id: UUID) -> Network | None:
        """
        Retrieve a network by its ID.
        :param network_id: The ID of the network to retrieve.
        :return: Network object or None if not found.
        """

    @abstractmethod
    async def filter(self,
                     status: RecordStatus | None = None,
                     cursor_id: str | None = None,
                     limit: int = 0,
                     forward: bool = True,
                     name: str | None = None,
                     ) -> tuple[list[Network], str | None, str | None]:
        """
        Filter networks based on visibility and registration status.
        :param status: The status of the network record to filter by.
        :param cursor_id: The ID of the last network from the previous page for pagination.
        :param limit: The maximum number of records to return. 0 means no limit.
        :param forward: Direction of pagination; True for forward, False for backward.
        :param name: Optional text the network name must contain, matched case-insensitively
            and literally (no pattern syntax).
        :return: A list of Network objects that match the filter criteria, with the cursor id
            for the first and last records if more records are available.
        """

    @abstractmethod
    async def save(self, network: Network) -> None:
        """
        Save a network to the repository.
        :param network: Network object to save.
        :return: None
        """

    @abstractmethod
    async def delete(self, network_id: str) -> None:
        """
        Delete a network by its ID.
        :param network_id: The ID of the network to delete.
        :return: None
        """

    @abstractmethod
    async def update(self, network: Network) -> None:
        """
        Update an existing network in the repository.
        :param network: Network object to update.
        :return: None
        """

    @abstractmethod
    async def update_status(self, network_id: UUID, new_status: RecordStatus) -> None:
        """
        Update the status of an existing network in the repository. This method only updates
        the status field of the network record to prevent data race conditions.
        :param network_id: The ID of the network to update.
        :param new_status: The new status to set for the network.
        """

    @abstractmethod
    async def search(self,
                     name: str | None = None,
                     description: str | None = None,
                     url: str | None = None,
                     ) -> tuple[list[Network], str | None]:
        """
        Search networks based on name, description, and URL of participating nodes.

        All search parameters are used for inclusion filtering; if multiple parameters are provided,
        only networks matching all criteria will be returned. White spaces are treated as literal
        characters.
        :param name: Optional name to search for.
        :param description: Optional description to search for.
        :param url: Optional URL to search for in nodes.
        :return: A list of Network objects that match the search criteria, with the next
            cursor ID if more records are available.
        """

    @abstractmethod
    async def count(self, status: RecordStatus | None = None) -> int:
        """
        Count the number of networks in the repository, optionally filtered by status.
        :param status: The status of the network record to filter by.
        :return: The count of networks matching the criteria.
        """

    @abstractmethod
    async def count_nodes(self, status: RecordStatus | None = None) -> int:
        """
        Count the total number of nodes across all networks in the repository,
        optionally filtered by network status.
        :param status: The status of the network record to filter by.
        :return: The count of nodes in networks matching the criteria.
        """


class NetworkAuditRepository(ABC):
    """
    An interface for database operations related to NetworkAudit entities.

    The repository is append-only; audit records cannot be modified or deleted once created.
    """

    @abstractmethod
    async def get(self, network_id: str, version: int) -> NetworkAudit | None:
        """
        Retrieve a network audit record by its network ID and version.
        :param network_id: The ID of the network.
        :param version: The version number of the audit record.
        :return: NetworkAudit object or None if not found.
        """

    @abstractmethod
    async def get_network_audits(self, network_id: UUID) -> list[NetworkAudit]:
        """
        Retrieve all audit records for a specific network, sorted by version in ascending order.
        :param network_id: The ID of the network.
        :return: A list of NetworkAudit objects.
        """

    @abstractmethod
    async def save(self, audit: NetworkAudit) -> None:
        """
        Save a network audit record to the repository.
        :param audit: NetworkAudit object to save.
        :return: None
        """
