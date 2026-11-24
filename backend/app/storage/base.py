from abc import ABC, abstractmethod
from pathlib import Path


class EvidenceStorage(ABC):
    """Storage abstraction supporting local filesystem now and S3/GCS object storage in hybrid cloud deployments."""

    @abstractmethod
    def save_bytes(self, relative_key: str, data: bytes) -> str:
        """Persist evidence bytes and return an opaque storage key/path."""

    @abstractmethod
    def read_bytes(self, stored_path: str) -> bytes:
        """Read evidence bytes safely, raising FileNotFoundError or ValueError on invalid paths."""

    @abstractmethod
    def exists(self, stored_path: str) -> bool:
        """Return True if the stored evidence object exists."""

    @abstractmethod
    def delete(self, stored_path: str) -> None:
        """Delete a stored object (used only for rollback on failed ingestion)."""

    @abstractmethod
    def resolve_safe_path(self, stored_path: str) -> Path:
        """Resolve and verify path containment within the configured vault root."""
