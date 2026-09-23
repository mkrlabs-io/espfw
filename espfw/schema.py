"""Result containers with JSON round-tripping, on top of dataclasses.

`BaseModel` subclasses are keyword-only dataclasses whose nested models and
enums are rebuilt from plain dicts on construction, so a memoized JSON file
loads back into the same types it was dumped from. There is no validation
beyond that; espfw has no third-party runtime dependencies.
"""

from __future__ import annotations

import json
import types
from dataclasses import MISSING, dataclass, field, fields
from dataclasses import Field as DataclassField
from enum import Enum
from pathlib import Path
from typing import Any, TypeVar, Union, get_args, get_origin, get_type_hints


class _ComputedProperty(property):
    pass


def computed_field(value: property) -> property:
    """Mark a property for inclusion in serialized model output."""
    return _ComputedProperty(value.fget, value.fset, value.fdel, value.__doc__)


def Field(
    default: Any = MISSING,
    *,
    default_factory: Any = MISSING,
    description: str | None = None,
) -> DataclassField:
    """A dataclass field whose `description` documents it in place."""
    metadata = {"description": description} if description else {}
    if default_factory is not MISSING:
        return field(default_factory=default_factory, metadata=metadata)
    if default is not MISSING:
        return field(default=default, metadata=metadata)
    return field(metadata=metadata)


class BaseModel:
    """Keyword-only dataclass with deterministic JSON conversion helpers."""

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)

        # A bare `x: list = []` is rejected by dataclasses; give it a factory.
        for name in getattr(cls, "__annotations__", {}):
            value = cls.__dict__.get(name, MISSING)
            if isinstance(value, list):
                setattr(cls, name, field(default_factory=lambda v=value: list(v)))
            elif isinstance(value, dict):
                setattr(cls, name, field(default_factory=lambda v=value: dict(v)))
            elif isinstance(value, set):
                setattr(cls, name, field(default_factory=lambda v=value: set(v)))

        # Installing this before dataclass() makes the generated initializer call
        # it. Nested dicts from JSON or existing callers are converted to their
        # annotated model and enum types here.
        if "__post_init__" not in cls.__dict__:
            cls.__post_init__ = BaseModel._coerce_fields  # type: ignore[attr-defined]
        dataclass(cls, kw_only=True)

    def _coerce_fields(self) -> None:
        hints = get_type_hints(type(self))
        for item in fields(self):
            value = getattr(self, item.name)
            setattr(self, item.name, _from_data(hints.get(item.name, item.type), value))

    def model_dump_json(self, *, indent: int | None = None) -> str:
        return json.dumps(to_data(self), indent=indent)

    @classmethod
    def model_validate_json(cls, text: str) -> Any:
        return _from_data(cls, json.loads(text))


def to_data(value: Any) -> Any:
    """Convert models, dataclasses and enums into JSON-safe stdlib values."""
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, BaseModel):
        out = {item.name: to_data(getattr(value, item.name)) for item in fields(value)}
        for base in reversed(type(value).__mro__):
            for name, descriptor in base.__dict__.items():
                if isinstance(descriptor, _ComputedProperty):
                    out[name] = to_data(getattr(value, name))
        return out
    if isinstance(value, dict):
        return {str(k) if isinstance(k, Enum) else k: to_data(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [to_data(v) for v in value]
    return value


def _from_data(annotation: Any, value: Any) -> Any:
    if value is None or annotation in (Any, None):
        return value
    if isinstance(annotation, TypeVar):
        return value

    origin = get_origin(annotation)
    args = get_args(annotation)
    if origin in (types.UnionType, Union):
        for option in args:
            if option is type(None):
                continue
            try:
                return _from_data(option, value)
            except (TypeError, ValueError):
                pass
        return value
    if origin is list:
        item_type = args[0] if args else Any
        return [_from_data(item_type, item) for item in value]
    if origin is tuple:
        item_types = args
        if len(item_types) == 2 and item_types[1] is Ellipsis:
            return tuple(_from_data(item_types[0], item) for item in value)
        return tuple(
            _from_data(item_types[i] if i < len(item_types) else Any, item)
            for i, item in enumerate(value)
        )
    if origin is set:
        item_type = args[0] if args else Any
        return {_from_data(item_type, item) for item in value}
    if origin is dict:
        key_type, value_type = args if len(args) == 2 else (Any, Any)
        return {
            _from_data(key_type, key): _from_data(value_type, item)
            for key, item in value.items()
        }
    if origin is not None and isinstance(origin, type) and issubclass(origin, BaseModel):
        annotation = origin

    if isinstance(annotation, type) and issubclass(annotation, BaseModel):
        if isinstance(value, annotation):
            return value
        if not isinstance(value, dict):
            raise TypeError(f"expected an object for {annotation.__name__}")
        names = {item.name for item in fields(annotation)}
        return annotation(**{key: item for key, item in value.items() if key in names})
    if isinstance(annotation, type) and issubclass(annotation, Enum):
        return value if isinstance(value, annotation) else annotation(value)
    if annotation in (int, float, str, bool):
        return annotation(value)
    return value
