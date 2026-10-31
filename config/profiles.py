from config.settings import CollectionProfile, ArtifactCategory
from config.artifact_catalog import ARTIFACT_CATALOG


def get_modules_for_profile(profile: CollectionProfile) -> list[str]:
    if profile == CollectionProfile.FULL:
        return list(ARTIFACT_CATALOG.keys())

    if profile == CollectionProfile.QUICK:
        return [
            mid for mid, info in ARTIFACT_CATALOG.items()
            if CollectionProfile.QUICK in info["profiles"]
        ]

    return []


def get_modules_for_category(category: ArtifactCategory) -> list[str]:
    return [
        mid for mid, info in ARTIFACT_CATALOG.items()
        if info["category"] == category
    ]


def get_available_profiles() -> list[str]:
    return [p.value for p in CollectionProfile]
