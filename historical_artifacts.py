from __future__ import annotations

import hashlib
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path

from historical_store import HistoricalStore


@dataclass(frozen=True)
class ArtifactReceipt:
    sha256: str
    size_bytes: int
    locator: str


class HistoricalArtifactStore:
    """Content-addressed raw-artifact storage for historical evidence.

    Raw source bytes live outside SQLite. SQLite stores a representation row
    containing locator, SHA-256, byte length, and acquisition state. Document
    identity remains separate from every physical/digital representation.
    """

    def __init__(self, root: str):
        self.root = Path(root).expanduser().resolve()
        self.objects = self.root / "objects" / "sha256"
        self.objects.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _digest(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    @staticmethod
    def _validate_digest(digest: str) -> None:
        if len(digest) != 64:
            raise ValueError("SHA-256 digest must contain 64 hexadecimal characters")
        try:
            bytes.fromhex(digest)
        except ValueError as exc:
            raise ValueError("SHA-256 digest is not hexadecimal") from exc

    def _path_for(self, digest: str) -> Path:
        self._validate_digest(digest)
        return self.objects / digest[:2] / digest[2:]

    @staticmethod
    def _locator(digest: str) -> str:
        return f"artifact:sha256:{digest}"

    def put_bytes(self, data: bytes) -> ArtifactReceipt:
        if not isinstance(data, bytes):
            raise TypeError("Historical artifacts must be captured as bytes")
        digest = self._digest(data)
        target = self._path_for(digest)
        target.parent.mkdir(parents=True, exist_ok=True)

        if target.exists():
            existing = target.read_bytes()
            if self._digest(existing) != digest or existing != data:
                raise ValueError(
                    "Content-addressed artifact path exists with invalid bytes"
                )
            return ArtifactReceipt(
                sha256=digest,
                size_bytes=len(data),
                locator=self._locator(digest),
            )

        fd, tmp = tempfile.mkstemp(
            prefix=f".{digest}.",
            suffix=".tmp",
            dir=str(target.parent),
        )
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            os.chmod(tmp, 0o600)
            os.replace(tmp, target)
            try:
                dir_fd = os.open(str(target.parent), os.O_RDONLY)
                try:
                    os.fsync(dir_fd)
                finally:
                    os.close(dir_fd)
            except OSError:
                pass
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)

        if not self.verify(digest, expected_size=len(data)):
            raise ValueError("Artifact verification failed after capture")

        return ArtifactReceipt(
            sha256=digest,
            size_bytes=len(data),
            locator=self._locator(digest),
        )

    def capture_file(self, path: str) -> ArtifactReceipt:
        return self.put_bytes(Path(path).expanduser().resolve().read_bytes())

    def verify(self, digest: str, *, expected_size: int | None = None) -> bool:
        target = self._path_for(digest)
        if not target.is_file():
            return False
        data = target.read_bytes()
        if expected_size is not None and len(data) != expected_size:
            return False
        return self._digest(data) == digest

    def read_bytes(self, digest: str) -> bytes:
        target = self._path_for(digest)
        data = target.read_bytes()
        if self._digest(data) != digest:
            raise ValueError("Historical artifact failed SHA-256 verification")
        return data

    def bind_document(
        self,
        store: HistoricalStore,
        document_id: str,
        receipt: ArtifactReceipt,
        *,
        representation_type: str = "raw_source",
        mime_type: str | None = None,
        source_url: str | None = None,
        preferred_for_review: bool = True,
        metadata: dict | None = None,
        representation_id: str | None = None,
    ) -> str:
        """Bind verified raw bytes as a RAW_CAPTURED representation."""
        if not self.verify(receipt.sha256, expected_size=receipt.size_bytes):
            raise ValueError("Cannot bind an unverified historical artifact")

        return store.register_document_representation(
            document_id=document_id,
            representation_type=representation_type,
            acquisition_state="RAW_CAPTURED",
            locator=receipt.locator,
            mime_type=mime_type,
            content_sha256=receipt.sha256,
            byte_length=receipt.size_bytes,
            source_url=source_url,
            raw_artifact=True,
            preferred_for_review=preferred_for_review,
            metadata=metadata,
            representation_id=representation_id,
        )
