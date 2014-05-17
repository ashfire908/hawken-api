# -*- coding: utf-8 -*-
# Caching interface

import msgpack
from abc import ABCMeta, abstractmethod
from functools import wraps
from itertools import count
from hawkenapi.util import copyappend


def encode(data):
    return msgpack.packb(data)


def decode(data):
    return msgpack.unpackb(data, encoding="utf-8")


class Expiry:
    default = 60  # 1 minute
    clan = 300  # 5 minutes
    game = 3600  # 1 hour
    globals = 10800  # 3 hours
    persistent = 25200  # 1 week
    server = 60  # 1 minute
    stats = 300  # 5 minutes
    status = 60  # 1 minute
    user = 300  # 5 minutes

    def get_class(self, eclass):
        return getattr(self, eclass, self.default)


class Cache(metaclass=ABCMeta):
    def __init__(self, prefix, lock_timeout=30, lock_poll=0.1):
        self.prefix = prefix
        self.lock_timeout = lock_timeout
        self.lock_poll = lock_poll
        self.expiry = Expiry()

    def format_key(self, identifier, *args, **kwargs):
        # Format: prefix:identifier:arg1.arg2#key=value|key=value
        # Create the base key
        key = self.prefix + ":" + identifier

        # Append the arguments
        if len(args) > 0:
            key += ":" + ".".join(args)

        # Append the keyword arguments
        kw = "|".join(sorted(k + "=" + v for k, v in kwargs.items() if v is not None))
        if len(kw) > 0:
            key += "#" + kw

        return key.lower()

    def format_lock_key(self, identifier, *args, **kwargs):
        # Format: lock$prefix:identifier:arg1.arg2#key=value|key=value
        return "lock$" + self.format_key(identifier, *args, **kwargs)

    def get_expiry(self, eclass):
        return self.expiry.get_class(eclass)

    @abstractmethod
    def get(self, key):
        pass

    @abstractmethod
    def get_multiple(self, keys):
        pass

    @abstractmethod
    def get_field(self, key, field):
        pass

    @abstractmethod
    def get_field_multiple(self, key, fields):
        pass

    @abstractmethod
    def get_field_values(self, key):
        pass

    @abstractmethod
    def set(self, key, value, expires):
        pass

    @abstractmethod
    def set_multiple(self, values, expires):
        pass

    @abstractmethod
    def set_field(self, key, values, expires):
        pass

    @abstractmethod
    def lock(self, key):
        pass


class RedisCache(Cache):
    def __init__(self, prefix, lock_timeout=30, lock_poll=0.1, url=None, **kwargs):
        super().__init__(prefix, lock_timeout=lock_timeout, lock_poll=lock_poll)

        # Import redis and setup the client
        import redis
        if url is not None:
            self.r = redis.StrictRedis.from_url(url, **kwargs)
        else:
            self.r = redis.StrictRedis(**kwargs)

    def get(self, key):
        # Retrieve key from cache
        cache = self.r.get(key)
        if not cache:
            # Cache miss
            return cache

        # Decode key
        return decode(cache)

    def get_multiple(self, keys):
        # Retrieve keys from cache
        for value in self.r.mget(keys):
            if value is None:
                # Cache miss
                yield value
            else:
                # Decode key
                yield decode(value)

    def get_field(self, key, field):
        # Retrieve field from cache
        cache = self.r.hget(key, field)
        if not cache:
            # Cache miss
            return cache

        # Decode field
        return decode(cache)

    def get_field_multiple(self, key, fields):
        # Retrieve the fields
        for value in self.r.hmget(key, fields):
            if value is None:
                # Cache miss
                yield value
            else:
                # Decode field
                yield decode(value)

    def get_field_values(self, key):
        # Check if the field exists
        if not self.r.exists(key):
            # Cache miss
            return None

        # Retrieve values from cache and decode
        return [decode(value) for value in self.r.hvals(key)]

    def set(self, key, value, expires):
        # Set the key value and expiry
        self.r.setex(key, expires, encode(value))

    def set_multiple(self, values, expires):
        # Create a pipeline
        pipe = self.r.pipeline()

        # Set the key values
        pipe.mset({k: encode(v) for k, v in values.items()})

        # Set the key expiry
        for k in values.keys():
            pipe.expire(k, expires)

        # Execute the pipelined requests
        pipe.execute()

    def set_field(self, key, values, expires):
        # Create a pipeline
        pipe = self.r.pipeline()

        # Delete the old hash
        pipe.delete(key)

        # Set the hash values
        pipe.hmset(key, {k: encode(v) for k, v in values.items()})

        # Set the hash expiry
        pipe.expire(key, expires)

        # Execute the pipelined requests
        pipe.execute()

    def lock(self, key):
        return self.r.lock(key, timeout=self.lock_timeout, sleep=self.lock_poll)


def nocache(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        kwargs.pop("cache_skip", None)
        kwargs.pop("cache_bypass", None)
        kwargs.pop("cache_expires", None)

        return f(*args, **kwargs)
    return wrap


class GuidList:
    def __init__(self, identifier, expiry=None):
        self.identifier = identifier
        self.expiry_class = expiry

    def __call__(self, f):
        @wraps(f)
        def wrap(client, *args, **kwargs):
            skip = kwargs.pop("cache_skip", False)
            bypass = kwargs.pop("cache_bypass", False)
            expires = kwargs.pop("cache_expires", None)
            if skip or client.cache is None:
                # No cache registered
                return f(client, *args, **kwargs)

            # Get the cache key
            ckey = client.cache.format_key(self.identifier, *args, **kwargs)

            if not bypass:
                # Check the cache
                cache = client.cache.get(ckey)
                if cache:
                    # Returned cached data
                    return cache

            # Acquire a lock
            with client.cache.lock(client.cache.format_lock_key(self.identifier, *args, **kwargs)):
                if not bypass:
                    # Verify the cache is still empty
                    cache = client.cache.get(ckey)
                    if cache:
                        # Returned cached data
                        return cache

                # Perform the wrapped request
                response = f(client, *args, **kwargs)

                if response:
                    # Cache the result
                    client.cache.set(ckey, response, expires or client.cache.get_expiry(self.expiry_class))

                return response

        return wrap


class ItemList:
    def __init__(self, identifier, key, expiry=None):
        self.identifier = identifier
        self.key = key
        self.expiry_class = expiry

    def __call__(self, f):
        @wraps(f)
        def wrap(client, *args, **kwargs):
            skip = kwargs.pop("cache_skip", False)
            bypass = kwargs.pop("cache_bypass", False)
            expires = kwargs.pop("cache_expires", None)
            if skip or client.cache is None:
                # No cache registered
                return f(client, *args, **kwargs)

            # Get the cache key
            ckey = client.cache.format_key(self.identifier, *args, **kwargs)

            if not bypass:
                # Check the cache
                cache = client.cache.get_field_values(ckey)
                if cache:
                    # Returned cached data
                    return cache

            # Acquire a lock
            with client.cache.lock(client.cache.format_lock_key(self.identifier, *args, **kwargs)):
                if not bypass:
                    # Verify the cache is still empty
                    cache = client.cache.get_field_values(ckey)
                    if cache:
                        # Returned cached data
                        return cache

                # Perform the wrapped request
                response = f(client, *args, **kwargs)

                if response:
                    # Cache the result
                    client.cache.set_field(ckey, {v[self.key]: v for v in response}, expires or client.cache.get_expiry(self.expiry_class))

                return response

        return wrap


class SingleItem:
    def __init__(self, identifier, listid=None, expiry=None):
        self.identifier = identifier
        self.listid = listid
        self.expiry_class = expiry

    def __call__(self, f):
        @wraps(f)
        def wrap(client, *args, **kwargs):
            skip = kwargs.pop("cache_skip", False)
            bypass = kwargs.pop("cache_bypass", False)
            expires = kwargs.pop("cache_expires", None)
            if skip or client.cache is None:
                # No cache registered
                return f(client, *args, **kwargs)

            # Get the cache key
            ckey = client.cache.format_key(self.identifier, *args, **kwargs)

            if not bypass:
                # Check the cache by key
                cache = client.cache.get(ckey)
                if cache:
                    # Return the cached data
                    return cache

                if self.listid:
                    # Check the cache for the associated item list
                    lkey = client.cache.format_key(self.listid, *args[:-1])
                    cache = client.cache.get_field(lkey, args[-1])
                    if cache:
                        # Return the cached data
                        return cache

            # Acquire a lock
            with client.cache.lock(client.cache.format_lock_key(self.identifier, *args, **kwargs)):
                if not bypass:
                    # Verify the cache is still empty
                    cache = client.cache.get(ckey)
                    if cache:
                        # Return the cached data
                        return cache

                # Perform the wrapped request
                response = f(client, *args, **kwargs)

                if response:
                    # Cache the result
                    client.cache.set(ckey, response, expires or client.cache.get_expiry(self.expiry_class))

                return response

        return wrap


class BatchItem:
    def __init__(self, identifier, key, listid=None, expiry=None):
        self.identifier = identifier
        self.key = key
        self.listid = listid
        self.expiry_class = expiry

    def __call__(self, f):
        @wraps(f)
        def wrap(client, *args, **kwargs):
            skip = kwargs.pop("cache_skip", False)
            bypass = kwargs.pop("cache_bypass", False)
            expires = kwargs.pop("cache_expires", None)
            if skip or client.cache is None:
                # No cache registered
                return f(client, *args, **kwargs)

            # Get the arguments
            kargs = list(args)
            items = kargs.pop()

            # Check if we have a single item
            if isinstance(items, str):
                # Get the cache key
                ckey = client.cache.format_key(self.identifier, *args, **kwargs)

                if not bypass:
                    # Check the cache by key
                    cache = client.cache.get(ckey)
                    if cache:
                        # Return the cached data
                        return cache

                    if self.listid:
                        # Check the cache for the associated item list
                        cache = client.cache.get_field(client.cache.format_key(self.listid, *kargs), items)
                        if cache:
                            # Return the cached data
                            return cache

                # Acquire a lock
                with client.cache.lock(client.cache.format_lock_key(self.identifier, *args, **kwargs)):
                    if not bypass:
                        # Verify the cache is still empty
                        cache = client.cache.get(ckey)
                        if cache:
                            # Return the cached data
                            return cache

                    # Perform the wrapped request
                    response = f(client, *args, **kwargs)

                    if response:
                        # Cache the result
                        client.cache.set(ckey, response, expires or client.cache.get_expiry(self.expiry_class))

                    return response

            # Perform a full batched lookup
            if not bypass:
                data = []
                misses = []
                miss_index = []
                # Check the cache by key
                ckeys = [client.cache.format_key(self.identifier, *copyappend(kargs, item), **kwargs) for item in items]
                for i, key, cache in zip(count(), items, client.cache.get_multiple(ckeys)):
                    if cache is None:
                        # Add it to the missed list
                        misses.append(key)
                        miss_index.append(i)

                    # Add the cache result to the output - misses are placeholders
                    data.append(cache)

                # Check for any cache misses
                if len(misses) == 0:
                    # Return cached data
                    return data

                # Check list cache
                if self.listid:
                    # Iterate over the misses index and the list cache result
                    miss = 0
                    hit = 0
                    for i, cache in zip(miss_index[:], client.cache.get_field_multiple(client.cache.format_key(self.listid, *kargs, **kwargs), misses)):
                        if cache is None:
                            # Increment the misses
                            miss += 1
                        else:
                            # Increment the hits
                            hit += 1

                            # Save the cache result in place
                            data[i] = cache

                            # Remove the item from the misses
                            del misses[i - hit]
                            del miss_index[miss]

                    # Check for any remaining cache misses
                    if len(misses) == 0:
                        # Return cached data
                        return data

            # Acquire a lock
            with client.cache.lock(client.cache.format_lock_key(self.identifier, *kargs, **kwargs)):
                if not bypass:
                    # Verify the cache is still empty
                    miss = 0
                    hit = 0
                    ckeys = [client.cache.format_key(self.identifier, *copyappend(kargs, miss), **kwargs) for miss in misses]
                    for i, cache in zip(miss_index[:], client.cache.get_multiple(ckeys)):
                        if cache is None:
                            # Increment the misses
                            miss += 1
                        else:
                            # Increment the hits
                            hit += 1

                            # Save the cache result in place
                            data[i] = cache

                            # Remove the item from the misses
                            del misses[i - hit]
                            del miss_index[miss]

                    # Check for any remaining cache misses
                    if len(misses) == 0:
                        # Return cached data
                        return data

                    # Perform the wrapped request
                    response = f(client, *copyappend(kargs, misses), **kwargs)
                else:
                    # Perform the wrapped request
                    response = f(client, *copyappend(kargs, items), **kwargs)

                if response:
                    # Cache the result
                    cache = {client.cache.format_key(self.identifier, *copyappend(kargs, v[self.key]), **kwargs): v for v in response}
                    client.cache.set_multiple(cache, expires or client.cache.get_expiry(self.expiry_class))

            # Break out of the lock so we aren't wasting lock time here
            if response and not bypass:
                # Fill in the remaining data
                for i, v in zip(miss_index, response):
                    data[i] = v

                # Return the data
                return data

            # The request failed or we bypassed the cache, pass back the value
            return response

        return wrap
