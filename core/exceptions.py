class PolarisError(Exception):
    pass


class CollectionError(PolarisError):
    pass


class ParsingError(PolarisError):
    pass


class HashVerificationError(PolarisError):
    pass


class CaseError(PolarisError):
    pass


class PermissionError(PolarisError):
    pass


class ManifestError(PolarisError):
    pass


class ReportError(PolarisError):
    pass


class TimelineError(PolarisError):
    pass


class PackagingError(PolarisError):
    pass


class ConfigurationError(PolarisError):
    pass
