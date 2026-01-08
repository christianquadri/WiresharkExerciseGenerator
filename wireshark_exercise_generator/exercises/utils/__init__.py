from __future__ import annotations

from functools import wraps
from inspect import signature
from typing import Any, Callable, Mapping, MutableMapping, Optional

Generator = Callable[..., Any]


def ensure_params(
    param_name: str,
    required: list[str],
    generators: Optional[dict[str, Generator]] = None,
    *,
    inplace: bool = False,
    allow_none: bool = False,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """
    Decorator that validates/augments a dict argument.

    Args:
        param_name: Name of the function argument that holds the dict (e.g., "params").
        required: Keys that must exist in the dict after decoration.
        generators: Optional mapping key -> callable used to generate missing values.
                    A generator may accept:
                      - no args
                      - (params)         where params is the dict being built
                      - (*args, **kwargs) original call args
                      - (params, *args, **kwargs)
                    The decorator will pass what the generator can accept.
        inplace: If True, mutate the input dict. If False, work on a shallow copy.
        allow_none: If False (default), a key with value None is treated as "missing"
                    and will be generated (if generator exists) or error.

    Raises:
        TypeError: If the target argument is not a mapping/dict-like.
        KeyError: If a required key is missing and no generator is provided for it.
    """
    generators = generators or {}

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        sig = signature(func)

        def _call_generator(gen: Generator, params: MutableMapping[str, Any], args, kwargs):
            # Try calling generator with the richest context first, then fallback.
            # This keeps the API flexible without forcing a strict signature.
            for attempt in (
                lambda: gen(params, *args, **kwargs),
                lambda: gen(*args, **kwargs),
                lambda: gen(params),
                lambda: gen(),
            ):
                try:
                    return attempt()
                except TypeError:
                    continue
            # If we get here, TypeError wasn't due to signature mismatch or it always mismatched.
            # Let it raise a meaningful error by trying the simplest call again.
            return gen()

        @wraps(func)
        def wrapper(*args, **kwargs):
            bound = sig.bind_partial(*args, **kwargs)
            if param_name not in bound.arguments:
                raise TypeError(
                    f"{func.__name__}(...): missing required argument '{param_name}' "
                    f"for ensure_params decorator."
                )

            raw_params = bound.arguments[param_name]
            if not isinstance(raw_params, Mapping):
                raise TypeError(
                    f"{func.__name__}(...): '{param_name}' must be a mapping/dict, "
                    f"got {type(raw_params).__name__}."
                )

            params: MutableMapping[str, Any]
            if inplace and isinstance(raw_params, dict):
                params = raw_params
            else:
                params = dict(raw_params)  # shallow copy

            def is_missing(key: str) -> bool:
                if key not in params:
                    return True
                if not allow_none and params.get(key) is None:
                    return True
                return False

            for key in required:
                if is_missing(key):
                    if key in generators:
                        params[key] = _call_generator(generators[key], params, args, kwargs)
                    else:
                        raise KeyError(
                            f"{func.__name__}(...): missing required key '{key}' "
                            f"in '{param_name}' and no generator provided."
                        )

            # Replace the bound argument (so func sees augmented params)
            bound.arguments[param_name] = params
            return func(*bound.args, **bound.kwargs)

        return wrapper

    return decorator
