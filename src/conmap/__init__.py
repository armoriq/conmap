from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("conmap")
except PackageNotFoundError:  # pragma: no cover - during local execution
    __version__ = "0.0.0"

__all__ = ["__version__"]
