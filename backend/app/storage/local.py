from pathlib import Path

from app.core.config import get_settings
from app.storage.base import EvidenceStorage


class LocalEvidenceStorage(EvidenceStorage):
    def __init__(self, root_dir: str | None = None) -> None:
        self._root = Path(root_dir or get_settings().evidence_vault_dir).resolve()
        self._root.mkdir(parents=True, exist_ok=True)

    @property
    def root(self) -> Path:
        return self._root

    def resolve_safe_path(self, stored_path: str) -> Path:
        candidate = Path(stored_path)
        if not candidate.is_absolute():
            # Support both relative vault keys and paths relative to CWD
            if candidate.parts and candidate.parts[0] == self._root.name:
                resolved = candidate.resolve()
            else:
                resolved = (self._root / candidate).resolve()
        else:
            resolved = candidate.resolve()

        if not resolved.is_relative_to(self._root):
            raise ValueError("Path traversal blocked: evidence path escapes configured vault root.")
        return resolved

    def save_bytes(self, relative_key: str, data: bytes) -> str:
        target = self.resolve_safe_path(relative_key)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        return str(target)

    def read_bytes(self, stored_path: str) -> bytes:
        target = self.resolve_safe_path(stored_path)
        if not target.exists() or not target.is_file():
            raise FileNotFoundError(f"Evidence object not found: {target.name}")
        return target.read_bytes()

    def exists(self, stored_path: str) -> bool:
        try:
            target = self.resolve_safe_path(stored_path)
            return target.exists() and target.is_file()
        except ValueError:
            return False

    def delete(self, stored_path: str) -> None:
        try:
            target = self.resolve_safe_path(stored_path)
            if target.exists():
                target.unlink(missing_ok=True)
        except ValueError:
            pass


def get_evidence_storage() -> EvidenceStorage:
    return LocalEvidenceStorage(get_settings().evidence_vault_dir)
