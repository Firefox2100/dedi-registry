import re
from uuid import UUID
from bson import ObjectId
from pymongo.asynchronous.database import AsyncDatabase
from pymongo.asynchronous.cursor import AsyncCursor

from dedi_registry.etc.enums import RecordStatus
from dedi_registry.etc.utils import reformat_pem
from dedi_registry.model.network import Network, NetworkAudit, NetworkRepository, NetworkAuditRepository


class MongoNetworkRepository(NetworkRepository):
    """
    MongoDB implementation of the NetworkRepository interface.
    """

    def __init__(self, db: AsyncDatabase):
        """
        Initialise the MongoNetworkRepository with a MongoDB database instance.
        :param db: MongoDB database instance.
        """
        self.db = db
        self.collection = db['networks']

    @staticmethod
    async def _paginate(cursor: AsyncCursor,
                        limit: int,
                        reverse_result: bool = False,
                        ) -> tuple[list[Network], str | None, str | None]:
        if limit > 0:
            cursor = cursor.limit(limit + 1)

        docs = []
        async for doc in cursor:
            docs.append(doc)

        has_next = 0 < limit < len(docs)
        if has_next:
            docs = docs[:limit]
            last_cursor_id = str(docs[-1]['_id'])
        else:
            last_cursor_id = None

        if reverse_result:
            docs.reverse()

        networks: list[Network] = []
        first_cursor_id = str(docs[0]['_id']) if docs else None
        for d in docs:
            d.pop('_id', None)
            networks.append(Network.model_validate(d))

        return networks, first_cursor_id, last_cursor_id

    async def get(self, network_id: UUID) -> Network | None:
        """
        Retrieve a network by its ID.
        :param network_id: The ID of the network to retrieve.
        :return: Network object or None if not found.
        """
        network_data = await self.collection.find_one({'networkId': str(network_id)}, {'_id': 0})

        if network_data:
            return Network.model_validate(network_data)

        return None

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
        query: dict = {}
        if status is not None:
            query['status'] = status.value
        if name:
            query['networkName'] = {'$regex': re.escape(name), '$options': 'i'}

        oid: ObjectId | None = None
        if cursor_id is not None:
            if not ObjectId.is_valid(cursor_id):
                raise ValueError(f'Invalid cursor ID: {cursor_id}')
            oid = ObjectId(cursor_id)

        if forward:
            if oid is not None:
                query['_id'] = {'$gt': oid}
            cursor = self.collection.find(query).sort('_id', 1)
            return await self._paginate(cursor, limit)
        else:
            if oid is not None:
                query['_id'] = {'$lt': oid}
            cursor = self.collection.find(query).sort('_id', -1)
            return await self._paginate(cursor, limit, reverse_result=True)

    async def save(self, network: Network) -> None:
        """
        Save a network to the repository.
        :param network: Network object to save.
        :return: None
        """
        network.public_key = reformat_pem(network.public_key)

        for node in network.nodes:
            node.public_key = reformat_pem(node.public_key)

        await self.collection.update_one(
            {'networkId': str(network.network_id)},
            {'$set': network.model_dump()},
            upsert=True
        )

    async def delete(self, network_id: str) -> None:
        """
        Delete a network by its ID.
        :param network_id: The ID of the network to delete.
        :return: None
        """
        await self.collection.delete_one({'networkId': network_id})

    async def update(self, network: Network) -> None:
        """
        Update an existing network in the repository.
        :param network: Network object to update.
        :return: None
        """
        await self.collection.update_one(
            {'networkId': str(network.network_id)},
            {'$set': network.model_dump()}
        )

    async def update_status(self, network_id: UUID, new_status: RecordStatus) -> None:
        """
        Update the status of an existing network in the repository. This method only updates
        the status field of the network record to prevent data race conditions.
        :param network_id: The ID of the network to update.
        :param new_status: The new status to set for the network.
        """
        await self.collection.update_one(
            {'networkId': str(network_id)},
            {'$set': {'status': new_status.value}}
        )

    async def search(self,
                     name: str | None = None,
                     description: str | None = None,
                     url: str | None = None,
                     ) -> list[Network]:
        """
        Search networks based on name, description, and URL of participating nodes.

        All search parameters are used for inclusion filtering; if multiple parameters are provided,
        only networks matching all criteria will be returned. White spaces are treated as literal
        characters.
        :param name: Optional name to search for.
        :param description: Optional description to search for.
        :param url: Optional URL to search for in nodes.
        :return: A list of Network objects that match the search criteria.
        """
        query = {}

        if name is not None:
            query['networkName'] = {'$regex': name, '$options': 'i'}
        if description is not None:
            query['description'] = {'$regex': description, '$options': 'i'}
        if url is not None:
            # Search within the nodes array for a matching URL
            query['nodes'] = {'$elemMatch': {'url': {'$regex': url, '$options': 'i'}}}

        cursor = self.collection.find(query, {'_id': 0}).sort('_id', 1)

        networks: list[Network] = []
        async for network_data in cursor:
            networks.append(Network.model_validate(network_data))

        return networks

    async def count(self, status: RecordStatus | None = None) -> int:
        """
        Count the number of networks in the repository, optionally filtered by status.
        :param status: The status of the network record to filter by.
        :return: The count of networks matching the criteria.
        """
        query = {}

        if status is not None:
            query['status'] = status.value

        return await self.collection.count_documents(query)

    async def count_nodes(self, status: RecordStatus | None = None) -> int:
        """
        Count the total number of nodes across all networks in the repository,
        optionally filtered by network status.
        :param status: The status of the network record to filter by.
        :return: The count of nodes in networks matching the criteria.
        """
        query = {}

        if status is not None:
            query['status'] = status.value

        pipeline = [
            {'$match': query},
            {'$unwind': '$nodes'},
            # Deduplicate based on the URL
            {'$group': {'_id': '$nodes.url'}},
            {'$count': 'nodeCount'}
        ]

        result = await self.collection.aggregate(pipeline)
        result = await result.to_list(length=1)

        if result:
            return result[0]['nodeCount']

        return 0


class MongoNetworkAuditRepository(NetworkAuditRepository):
    """
    A MongoDB implementation of the NetworkAuditRepository interface.
    """

    def __init__(self, db: AsyncDatabase):
        """
        Initialise the MongoUserRepository with a MongoDB database instance.
        :param db: MongoDB database instance.
        """
        self.db = db
        self.collection = db['networks.audit']

    async def get(self, network_id: str, version: int) -> NetworkAudit | None:
        """
        Retrieve a network audit record by its network ID and version.
        :param network_id: The ID of the network.
        :param version: The version number of the audit record.
        :return: NetworkAudit object or None if not found.
        """
        audit_data = await self.collection.find_one(
            {'networkId': network_id, 'version': version},
            {'_id': 0}
        )

        if audit_data:
            return NetworkAudit.model_validate(audit_data)

        return None

    async def get_network_audits(self, network_id: UUID) -> list[NetworkAudit]:
        """
        Retrieve all audit records for a specific network, sorted by version in ascending order.
        :param network_id: The ID of the network.
        :return: A list of NetworkAudit objects.
        """
        cursor = self.collection.find(
            {'networkId': str(network_id)},
            {'_id': 0}
        ).sort('version', 1)

        audits: list[NetworkAudit] = []
        async for audit_data in cursor:
            audits.append(NetworkAudit.model_validate(audit_data))

        return audits

    async def save(self, audit: NetworkAudit) -> None:
        """
        Save a network audit record to the repository.
        :param audit: NetworkAudit object to save.
        :return: None
        """
        existing_doc = await self.collection.find_one(
            {'networkId': str(audit.network_id), 'version': audit.version},
            {'_id': 1}
        )

        if existing_doc:
            raise ValueError(f'Network audit record for network ID {audit.network_id} '
                             f'and version {audit.version} already exists.')

        await self.collection.insert_one(audit.model_dump())
