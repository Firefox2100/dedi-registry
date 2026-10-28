import hashlib
import time
import threading

import pytest

from dedi_registry.cache.memory_driver import MemoryCache, MemoryChallengeCache
from dedi_registry.etc.utils import (
    ThreadSafeDict,
    ThreadSafeList,
    ThreadSafeQueue,
    reformat_pem,
    validate_hash_challenge,
)


def _solve(nonce: str, difficulty: int) -> str:
    counter = 0
    while True:
        data = f'{nonce}{counter}'.encode()
        bits = bin(int(hashlib.sha256(data).hexdigest(), 16))[2:].zfill(256)
        if bits.startswith('0' * difficulty):
            return str(counter)
        counter += 1


class TestThreadSafeDict:
    def test_mapping_operations(self):
        data = ThreadSafeDict({'a': 1})
        data['b'] = 2

        assert data['a'] == 1
        assert 'b' in data
        assert len(data) == 2
        assert data.get('missing', 'x') == 'x'
        assert sorted(data) == ['a', 'b']
        assert sorted(data.keys()) == ['a', 'b']
        assert sorted(data.values()) == [1, 2]
        assert sorted(data.items()) == [('a', 1), ('b', 2)]

        del data['a']
        assert 'a' not in data
        assert data.pop('b') == 2
        assert data.pop('b', 'gone') == 'gone'

        data.update({'c': 3})
        assert data.copy() == {'c': 3}
        data.clear()
        assert len(data) == 0

    def test_lock_is_reentrant(self):
        data = ThreadSafeDict()
        with data.lock:
            data['a'] = 1
        assert data['a'] == 1

    def test_iteration_survives_mutation(self):
        data = ThreadSafeDict({'a': 1, 'b': 2})
        for key in data:
            del data[key]
        assert len(data) == 0

    def test_concurrent_writes(self):
        data = ThreadSafeDict()

        def write(offset):
            for i in range(200):
                data[offset + i] = i

        threads = [threading.Thread(target=write, args=(n * 1000,)) for n in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert len(data) == 800


class TestThreadSafeList:
    def test_list_operations(self):
        items = ThreadSafeList([3, 1])
        items.append(2)
        items.extend([5, 4])
        items.insert(0, 0)

        assert len(items) == 6
        assert items[0] == 0
        assert 5 in items
        assert items.index(5) == 4
        assert items.count(1) == 1

        items[0] = 9
        assert items[0] == 9
        del items[0]
        items.remove(5)
        assert items.pop() == 4

        items.sort()
        assert list(items) == [1, 2, 3]
        items.reverse()
        assert list(items) == [3, 2, 1]

        copied = items.copy()
        assert isinstance(copied, ThreadSafeList)
        assert list(copied) == [3, 2, 1]

        items.clear()
        assert len(items) == 0

    def test_lock_is_reentrant(self):
        items = ThreadSafeList()
        with items.lock:
            items.append(1)
        assert list(items) == [1]


class TestThreadSafeQueue:
    def test_fifo_order(self):
        queue = ThreadSafeQueue()
        assert queue.empty()

        queue.put('a')
        queue.put('b')

        assert len(queue) == 2
        assert queue.size() == 2
        assert list(queue) == ['a', 'b']
        assert queue.peek() == 'a'
        assert queue.get() == 'a'
        assert queue.get() == 'b'
        assert queue.empty()

    def test_empty_queue_raises(self):
        queue = ThreadSafeQueue()

        with pytest.raises(IndexError):
            queue.get()
        with pytest.raises(IndexError):
            queue.peek()

    def test_clear(self):
        queue = ThreadSafeQueue()
        queue.put(1)
        queue.clear()
        assert queue.empty()


class TestValidateHashChallenge:
    def test_accepts_valid_solution(self):
        solution = _solve('nonce', 8)
        assert validate_hash_challenge('nonce', 8, solution)

    def test_rejects_invalid_solution(self):
        solution = _solve('nonce', 8)
        assert not validate_hash_challenge('other-nonce', 16, solution)

    def test_zero_difficulty_always_passes(self):
        assert validate_hash_challenge('nonce', 0, 'anything')


class TestReformatPem:
    HEADER = '-----BEGIN PUBLIC KEY-----'
    FOOTER = '-----END PUBLIC KEY-----'

    def test_wraps_body_at_64_characters(self):
        body = 'A' * 150
        result = reformat_pem(f'{self.HEADER}{body}{self.FOOTER}')

        lines = result.split('\n')
        assert lines[0] == self.HEADER
        assert lines[-1] == self.FOOTER
        assert [len(line) for line in lines[1:-1]] == [64, 64, 22]

    def test_normalises_existing_line_breaks(self):
        body = 'B' * 100
        messy = f'{self.HEADER}\r\n{body[:30]}\\n{body[30:]}\n{self.FOOTER}\n'

        assert reformat_pem(messy) == reformat_pem(f'{self.HEADER}{body}{self.FOOTER}')

    def test_rejects_other_formats(self):
        with pytest.raises(ValueError):
            reformat_pem('-----BEGIN PRIVATE KEY-----abc-----END PRIVATE KEY-----')


class TestMemoryChallengeCache:
    async def test_round_trip(self):
        cache = MemoryChallengeCache()
        await cache.save_challenge('round-trip', 12)

        assert await cache.get_challenge('round-trip') == 12

    async def test_unknown_challenge(self):
        assert await MemoryChallengeCache().get_challenge('never-saved') is None

    async def test_expired_challenge(self):
        cache = MemoryChallengeCache()
        await cache.save_challenge('expired', 4)
        MemoryChallengeCache._challenges['expired']['timestamp'] = time.time() - 301

        assert await cache.get_challenge('expired') is None

    def test_cache_exposes_challenge_cache(self):
        assert isinstance(MemoryCache().challenge, MemoryChallengeCache)
