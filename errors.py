class Error(Exception):
    pass


class FilterAnalysisError(Error):
    pass


class FilterCompositionError(Error):
    pass


class UnimplementedError(Error):
    pass


class UnsupportedAFIerror(Error):
    pass


class IPparseError(Error):
    pass
