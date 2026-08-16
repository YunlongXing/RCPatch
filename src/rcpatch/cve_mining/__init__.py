"""Public entry points for RCPatch CVE collection."""

from rcpatch.cve_mining.collection import CVECollectionService
from rcpatch.cve_mining.dataset import CVEDatasetBuildCase, CVERootCauseDatasetBuilder
from rcpatch.cve_mining.mining import CVERootCauseMiner
from rcpatch.cve_mining.patches import CVEPatchExtractor
from rcpatch.cve_mining.patterns import RootCausePatternMiner
from rcpatch.cve_mining.semantic_alignment import CVESemanticAligner
from rcpatch.cve_mining.sources import (
    CVEListV5Adapter,
    CVESourceAdapter,
    CollectionSource,
    GitHubSecurityAdvisoryAdapter,
    NVDJSONFeedAdapter,
    ProjectAdvisoryAdapter,
    get_source_adapter,
)

__all__ = [
    "CVECollectionService",
    "CVEDatasetBuildCase",
    "CVERootCauseMiner",
    "CVERootCauseDatasetBuilder",
    "CVEPatchExtractor",
    "CVESemanticAligner",
    "RootCausePatternMiner",
    "CVEListV5Adapter",
    "CVESourceAdapter",
    "CollectionSource",
    "GitHubSecurityAdvisoryAdapter",
    "NVDJSONFeedAdapter",
    "ProjectAdvisoryAdapter",
    "get_source_adapter",
]
