"""APi-related helpers
"""
from enum import Enum
from uuid import uuid4, UUID
from pathlib import Path
from typing import Optional
from yarl import URL
from .config import CONFIG
from .platform import get_case_dir

PROCESSING_DIR = Path(
    CONFIG.get_(
        'datashark',
        'service',
        'processing',
        'directory',
        type=Path,
        default=get_case_dir('processing'),
    )
)


class ArtifactURL:
    """Artifact url"""

    def __init__(self, url: URL):
        self._url = url

    @property
    def url(self) -> URL:
        return self._url

    def as_path(self) -> Path:
        """Wraps path part of the url into pathlib.Path"""
        return Path(self._url.path)


class Artifact(dict):
    """Keeps track of an artifact to be processed"""

    LOCALHOST = 'localhost'

    def __init__(
        self,
        url: ArtifactURL,
        parent: Optional['Artifact'] = None,
    ):
        super().__init__()
        self['uuid'] = uuid4()
        self['url'] = url
        self['parent'] = parent.uuid if parent else None

    def __repr__(self):
        return f"Artifact(uuid='{self.uuid}', parent='{self.parent}', url='{self.url.human_repr()}')"

    @property
    def uuid(self) -> UUID:
        """Unique Identifier for this artifact"""
        return self['uuid']

    @property
    def parent(self) -> UUID:
        """Unique Identifier for this artifact"""
        return self['parent']

    @property
    def filepath(self) -> Path:
        """Artefact path in processing directory"""
        if self.url.host == self.LOCALHOST:
            return Path(self.url.path)
        return PROCESSING_DIR / str(self.uuid)

    @property
    def url(self) -> ArtifactURL:
        """URL of the artifact to be processed in its original context"""
        return self['url']


class Status(Enum):
    """
    Overall processing result:
        - "success" means that the plugin produced everything as intented
        - "partial" means that the plugin encountered non fatal errors and might
          have produced partial results, manual review is advised.
        - "failure" means that the plugin failed to process given artifact,
          manual review is the only solution.
    """

    SUCCESS = "success"
    PARTIAL = "partial"
    FAILURE = "failure"


class Result(dict):
    """Keeps track of plugin processing result of artifact"""

    def __init__(
        self,
        plugin: 'Plugin',
        status: Status,
        artifact: Artifact,
    ):
        super().__init__()
        self['plugin'] = plugin.name
        self['status'] = status
        self['artifact'] = artifact

    def __repr__(self):
        return f"Result(plugin='{self['plugin']}', status='{self['status'].name}', artifact={self['artifact']})"

    @property
    def plugin(self) -> str:
        """Name of the plugin producing this result"""
        return self['plugin']

    @property
    def status(self) -> Status:
        """Overall status of processed object"""
        return self['status']

    @property
    def artifact(self) -> Artifact:
        """Processed artifact"""
        return self['artifact']
