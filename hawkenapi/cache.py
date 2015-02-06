# -*- coding: utf-8 -*-
# Caching interface
# Copyright (c) 2013-2014 Andrew Hampe

from collections import OrderedDict
from functools import wraps
from inspect import signature, Parameter
from hawkenapi.util import copyappend

try:
    import msgpack
    import redis
    from redis.exceptions import WatchError
except ImportError as e:
    _failedload = (True, e)
else:
    _failedload = (False, )


def cache_args(f, *args, **kwargs):
    # Manually bind arguments since signature().bind().args/kwargs is broken
    sig = signature(f)
    bound = sig.bind(*args, **kwargs)
    new_args = []
    new_kwargs = OrderedDict()
    for param in sig.parameters.values():
        if param.kind == Parameter.POSITIONAL_ONLY:
            new_args.append(bound.arguments[param.name])
        elif param.kind == Parameter.POSITIONAL_OR_KEYWORD:
            if param.default == Parameter.empty:
                new_args.append(bound.arguments[param.name])
            elif param.name in bound.arguments and bound.arguments[param.name] != param.default:
                new_kwargs[param.name] = bound.arguments[param.name]
        elif param.kind == Parameter.VAR_POSITIONAL:
            if param.name in bound.arguments:
                new_args.extend(bound.arguments[param.name])
        elif param.kind == Parameter.KEYWORD_ONLY:
            if param.name in bound.arguments:
                new_kwargs[param.name] = bound.arguments[param.name]
        # VAR_KEYWORD
        elif param.name in bound.arguments:
            for name, value in bound.arguments[param.name]:
                new_kwargs[name] = value

    return args[1:], new_kwargs


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
        if _failedload[0]:
            raise _failedload[1]

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

            for k, v in kwargs.items():
                if isinstance(v, str):
                    kwarg_pairs.append(k + "=" + v)
                else:
                    # Assume it's a list
                    kwarg_pairs.append(k + "=" + ",".join(sorted(v)))

            key += "#" + "|".join(kwarg_pairs)

        return key.lower()

    def get_expiry(self, eclass):
        return self.expiry.get_class(eclass)

    def encode(self, data):
        return msgpack.packb(data)

    def decode(self, data):
        if not data:
            return data
        return msgpack.unpackb(data, encoding="utf-8")


def nocache(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        kwargs.pop("cache_skip", None)
        kwargs.pop("cache_bypass", None)

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
            cache = client.cache
            if skip or cache is None:
                # No cache registered
                return f(client, *args, **kwargs)
            expires = cache.get_expiry(self.expiry_class)
            r = cache.redis

            # Update the positional args and verify the args work for the wrapped function
            args, kwargs = cache_args(f, client, *args, **kwargs)

            # Get the cache key
            ckey = cache.format_key(self.identifier, *args, **kwargs)

            # Open a pipeline
            with r.pipeline() as pipe:
                if not bypass:
                    # Watch the key
                    pipe.watch(ckey)

                    # Check the cache
                    data = cache.decode(pipe.get(ckey))
                    if data:
                        # Returned cached data
                        return data

                # Perform the wrapped request
                response = f(client, *args, **kwargs)

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

        return wrap


class ItemList:
    def __init__(self, list_identifier, identifier, key, expiry=None):
        self.list_identifier = list_identifier
        self.identifier = identifier
        self.key = key
        self.expiry_class = expiry

    def __call__(self, f):
        @wraps(f)
        def wrap(client, *args, **kwargs):
            skip = kwargs.pop("cache_skip", False)
            bypass = kwargs.pop("cache_bypass", False)
            cache = client.cache
            if skip or cache is None:
                # No cache registered
                return f(client, *args, **kwargs)
            expires = cache.get_expiry(self.expiry_class)
            r = cache.redis

            # Update the positional args and verify the args work for the wrapped function
            args, kwargs = cache_args(f, client, *args, **kwargs)

            # Get the list key
            lkey = cache.format_key(self.list_identifier, *args, **kwargs)

            # Open a pipeline
            with r.pipeline() as pipe:
                if not bypass:
                    # Watch the key
                    pipe.watch(lkey)

                    # Check the cache
                    cache_list = [v.decode() for v in pipe.smembers(lkey)]
                    if cache_list:
                        # Load cached data
                        ckeys = [cache.format_key(self.identifier, *copyappend(args, key), **kwargs) for key in cache_list]
                        data = [cache.decode(v) for v in pipe.mget(ckeys) if v is not None]
                        # Check if all the keys are intact
                        if len(ckeys) == len(data):
                            # Return the cached data
                            return data

                # Perform the wrapped request
                response = f(client, *args, **kwargs)

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
                    for k, v in data.items():
                        pipe.setex(k, expires, v)

                    try:
                        pipe.execute()
                    except WatchError:
                        # Ignore it and just return the result
                        pass

            return response

        return wrap


class SingleItem:
    def __init__(self, identifier, expiry=None):
        self.identifier = identifier
        self.expiry_class = expiry

    def __call__(self, f):
        @wraps(f)
        def wrap(client, *args, **kwargs):
            skip = kwargs.pop("cache_skip", False)
            bypass = kwargs.pop("cache_bypass", False)
            cache = client.cache
            if skip or cache is None:
                # No cache registered
                return f(client, *args, **kwargs)
            expires = cache.get_expiry(self.expiry_class)
            r = cache.redis

            # Update the positional args and verify the args work for the wrapped function
            args, kwargs = cache_args(f, client, *args, **kwargs)

            # Get the cache key
            ckey = cache.format_key(self.identifier, *args, **kwargs)

            # Open a pipeline
            with r.pipeline() as pipe:
                if not bypass:
                    # Watch the key
                    pipe.watch(ckey)

                    # Check the cache
                    data = cache.decode(pipe.get(ckey))
                    if data:
                        # Returned cached data
                        return data

                # Perform the wrapped request
                response = f(client, *args, **kwargs)

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

        return wrap


class BatchItem:
    def __init__(self, identifier, key, expiry=None):
        self.identifier = identifier
        self.key = key
        self.expiry_class = expiry

    def __call__(self, f):
        @wraps(f)
        def wrap(client, *args, **kwargs):
            skip = kwargs.pop("cache_skip", False)
            bypass = kwargs.pop("cache_bypass", False)
            cache = client.cache
            if skip or cache is None:
                # No cache registered
                return f(client, *args, **kwargs)
            expires = cache.get_expiry(self.expiry_class)
            r = cache.redis

            # Update the positional args and verify the args work for the wrapped function
            args, kwargs = cache_args(f, client, *args, **kwargs)

            # Get the arguments
            *kargs, items = args

            # Check if we have a single item
            if isinstance(items, str):
                # Get the cache key
                ckey = cache.format_key(self.identifier, *args, **kwargs)

                # Open a pipeline
                with r.pipeline() as pipe:
                    if not bypass:
                        # Watch the key
                        pipe.watch(ckey)

                        # Check the cache
                        data = cache.decode(pipe.get(ckey))
                        if data:
                            # Returned cached data
                            return data

                    # Perform the wrapped request
                    response = f(client, *args, **kwargs)

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

            # Get the cache keys
            ckeys = [cache.format_key(self.identifier, *copyappend(kargs, item), **kwargs) for item in items]

            # Perform a full batched lookup
            data = []
            with r.pipeline() as pipe:
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
                    response = f(client, *copyappend(kargs, misses), **kwargs)
                else:
                    # Perform the wrapped request
                    response = f(client, *copyappend(kargs, items), **kwargs)

                if response:
                    # Cache the result
                    pipe.multi()
                    for v in response:
                        pipe.setex(cache.format_key(self.identifier, *copyappend(kargs, v[self.key]), **kwargs), expires, cache.encode(v))
                    try:
                        pipe.execute()
                    except WatchError:
                        # Only populate the keys that are missing
                        with r.pipeline() as inner_pipe:
                            for v in response:
                                inner_pipe.set(cache.format_key(self.identifier, *copyappend(kargs, v[self.key]), **kwargs), cache.encode(v), ex=expires, nx=True)
                            inner_pipe.execute()

            if response and not bypass:
                # Add in the missing data
                data.extend(response)

                # Return the data
                return data

            # The request failed or we bypassed the cache, pass back the value
            return response

        return wrap
