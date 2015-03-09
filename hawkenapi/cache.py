# -*- coding: utf-8 -*-
# Caching interface
# Copyright (c) 2013-2015 Andrew Hampe

from functools import wraps
from hawkenapi.endpoints import RequestType
from hawkenapi.util import copyappend, bind_wrapped_arguments

try:
    import msgpack
    import redis
    from redis.exceptions import WatchError
except ImportError as e:
    IMPORT_RESULT = (True, e)
else:
    IMPORT_RESULT = (False, )


class Expiry:
    default = 60  # 1 minute
    clan = 300  # 5 minutes
    game = 3600  # 1 hour
    globals = 10800  # 3 hours
    persistent = 604800  # 1 week
    server = 60  # 1 minute
    stats = 300  # 5 minutes
    status = 60  # 1 minute
    user = 300  # 5 minutes

    def get_class(self, eclass):
        return getattr(self, eclass, self.default)


class Cache:
    def __init__(self, prefix, expiry=None, url=None, **kwargs):
        self.prefix = prefix
        if expiry is not None:
            self.expiry = expiry
        else:
            self.expiry = Expiry()

        # Check if we successfully imported our deps
        if IMPORT_RESULT[0]:
            raise IMPORT_RESULT[1]

        # Setup the client
        if url is not None:
            self.redis = redis.StrictRedis.from_url(url, **kwargs)
        else:
            self.redis = redis.StrictRedis(**kwargs)

    def format_key(self, identifier, *args, **kwargs):
        # Format: prefix:identifier:arg1.arg2#key=value|key=value
        # Create the base key
        key = self.prefix + ":" + identifier

        # Append the arguments
        if len(args) > 0:
            key += ":" + ".".join(args)

        # Append the keyword arguments
        if len(kwargs) > 0:
            kwarg_pairs = []

            for name, value in kwargs.items():
                if isinstance(value, str):
                    kwarg_pairs.append(name + "=" + value)
                else:
                    # Assume it's a list
                    kwarg_pairs.append(name + "=" + ",".join(sorted(value)))

            key += "#" + "|".join(kwarg_pairs)

        return key.lower()

    def get_expiry(self, eclass):
        return self.expiry.get_class(eclass)

    @staticmethod
    def encode(data):
        return msgpack.packb(data)

    @staticmethod
    def decode(data):
        if not data:
            return data
        return msgpack.unpackb(data, encoding="utf-8")


class CacheWrapper:
    def __init__(self, identifier, list_identifier=None, key=None, expiry=None):
        self.identifier = identifier
        self.expiry_class = expiry
        self.list_identifier = list_identifier
        self.key = key

    def __call__(self, func):
        request_type = RequestType.get(func)

        if request_type == RequestType.item_list and self.list_identifier is None:
            raise ValueError("Item list request selected but no list identifier given")
        if request_type in (RequestType.item_list, RequestType.batch_item) and self.key is None:
            raise ValueError("Key-dependant request selected but no key given")

        @wraps(func)
        def wrap(client, *args, **kwargs):
            skip = kwargs.pop("cache_skip", False)
            bypass = kwargs.pop("cache_bypass", False)

            if skip or client.cache is None:
                # No cache registered
                return func(client, *args, **kwargs)

            # Update the positional args and verify the args work for the wrapped function
            args, kwargs = bind_wrapped_arguments(func, client, *args, **kwargs)

            if request_type == RequestType.guid_list:
                return self.cache_guid(func, client, bypass, *args, **kwargs)

            if request_type == RequestType.item_list:
                return self.cache_list(func, client, bypass, *args, **kwargs)

            if request_type == RequestType.single_item:
                return self.cache_item(func, client, bypass, *args, **kwargs)

            if request_type == RequestType.batch_item:
                return self.cache_batch(func, client, bypass, *args, **kwargs)

            raise ValueError("Unsupported request type")

        return wrap

    def cache_guid(self, func, client, bypass, *args, **kwargs):
        # Init
        cache = client.cache
        expires = cache.get_expiry(self.expiry_class)
        redis_client = cache.redis

        # Get the cache key
        ckey = cache.format_key(self.identifier, *args, **kwargs)

        # Open a pipeline
        with redis_client.pipeline() as pipe:
            if not bypass:
                # Watch the key
                pipe.watch(ckey)

                # Check the cache
                data = pipe.smembers(ckey)
                if len(data) > 0:
                    # Returned cached data
                    return data

            # Perform the wrapped request
            response = func(client, *args, **kwargs)

            if response:
                # Cache the result
                pipe.multi()
                pipe.sadd(ckey, *response)
                pipe.expire(ckey, expires)
                try:
                    pipe.execute()
                except WatchError:
                    # Ignore it and just return the result
                    pass

        return response

    def cache_list(self, func, client, bypass, *args, **kwargs):
        # Init
        cache = client.cache
        expires = cache.get_expiry(self.expiry_class)
        redis_client = cache.redis

        # Get the list key
        lkey = cache.format_key(self.list_identifier, *args, **kwargs)

        # Open a pipeline
        with redis_client.pipeline() as pipe:
            if not bypass:
                # Watch the key
                pipe.watch(lkey)

                # Check the cache
                cache_list = pipe.smembers(lkey)
                if cache_list:
                    # Load cached data
                    ckeys = [cache.format_key(self.identifier, *copyappend(args, key), **kwargs) for key in cache_list]
                    data = [cache.decode(v) for v in pipe.mget(ckeys) if v is not None]
                    # Check if all the keys are intact
                    if len(ckeys) == len(data):
                        # Return the cached data
                        return data

            # Perform the wrapped request
            response = func(client, *args, **kwargs)

            if response:
                # Build the keys list and data dict
                keys = []
                data = {}
                for value in response:
                    keys.append(value[self.key])
                    data[cache.format_key(self.identifier, *copyappend(args, value[self.key]), **kwargs)] = cache.encode(value)

                # Cache the result
                pipe.multi()

                # Update the set
                pipe.delete(lkey)
                pipe.sadd(lkey, *keys)
                pipe.expire(lkey, expires)

                # Set the data
                for key, data in data.items():
                    pipe.setex(key, expires, data)

                try:
                    pipe.execute()
                except WatchError:
                    # Ignore it and just return the result
                    pass

        return response

    def cache_item(self, func, client, bypass, *args, **kwargs):
        # Init
        cache = client.cache
        expires = cache.get_expiry(self.expiry_class)
        redis_client = cache.redis

        # Get the cache key
        ckey = cache.format_key(self.identifier, *args, **kwargs)

        # Open a pipeline
        with redis_client.pipeline() as pipe:
            if not bypass:
                # Watch the key
                pipe.watch(ckey)

                # Check the cache
                data = cache.decode(pipe.get(ckey))
                if data:
                    # Returned cached data
                    return data

            # Perform the wrapped request
            response = func(client, *args, **kwargs)

            if response:
                # Cache the result
                pipe.multi()
                pipe.setex(ckey, expires, cache.encode(response))
                try:
                    pipe.execute()
                except WatchError:
                    # Ignore it and just return the result
                    pass

        return response

    def cache_batch(self, func, client, bypass, *args, **kwargs):
        # Init
        cache = client.cache
        expires = cache.get_expiry(self.expiry_class)
        redis_client = cache.redis

        # Get the arguments
        *kargs, items = args

        # Check if we have a single item
        if isinstance(items, str):
            self.cache_item(func, client, bypass, *args, **kwargs)

        if len(items) == 0:
            # Nothing to cache, pass onto wrapped method
            return func(client, *args, **kwargs)

        # Get the cache keys
        ckeys = [cache.format_key(self.identifier, *copyappend(kargs, item), **kwargs) for item in items]

        # Perform a full batched lookup
        data = []
        with redis_client.pipeline() as pipe:
            # Watch the keys
            pipe.watch(ckeys)

            if not bypass:
                misses = []
                # Check the cache by key
                for key, value in zip(items, (cache.decode(v) for v in pipe.mget(ckeys))):
                    if value is None:
                        misses.append(key)
                    else:
                        data.append(value)

                # Check for any cache misses
                if len(misses) == 0:
                    # Return cached data
                    return data

                # Perform the wrapped request
                response = func(client, *copyappend(kargs, misses), **kwargs)
            else:
                # Perform the wrapped request
                response = func(client, *copyappend(kargs, items), **kwargs)

            if response:
                # Cache the result
                pipe.multi()
                for item in response:
                    pipe.setex(cache.format_key(self.identifier, *copyappend(kargs, item[self.key]), **kwargs), expires, cache.encode(item))
                try:
                    pipe.execute()
                except WatchError:
                    # Only populate the keys that are missing
                    with redis_client.pipeline() as inner_pipe:
                        for item in response:
                            inner_pipe.set(cache.format_key(self.identifier, *copyappend(kargs, item[self.key]), **kwargs), cache.encode(item), ex=expires, nx=True)
                        inner_pipe.execute()

        if response and not bypass:
            # Add in the missing data
            data.extend(response)

            # Return the data
            return data

        # The request failed or we bypassed the cache, pass back the value
        return response

    @staticmethod
    def no_cache(func):
        @wraps(func)
        def wrap(client, *args, **kwargs):
            kwargs.pop("cache_skip", None)
            kwargs.pop("cache_bypass", None)

            return func(client, *args, **kwargs)
        return wrap
