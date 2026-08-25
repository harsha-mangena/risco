from __future__ import annotations


class RiscoError(Exception):
    exit_code = 1


class PolicyError(RiscoError):
    exit_code = 2


class ToolUnavailable(RiscoError):
    def __init__(self, tool: str, detail: str = ""):
        super().__init__(f"tool unavailable: {tool}" + (f": {detail}" if detail else ""))
        self.tool = tool
        self.detail = detail


class ParseFailure(RiscoError):
    def __init__(self, what: str, detail: str = ""):
        super().__init__(f"parse failure: {what}" + (f": {detail}" if detail else ""))
        self.what = what


class ScannerUnavailable(ToolUnavailable):
    def __init__(self, detail: str = ""):
        super().__init__("tree-sitter scanner", detail)


class IndexMissing(RiscoError):
    pass


class GithubApiError(RiscoError):
    def __init__(self, status: int, message: str, rate_limited: bool = False):
        super().__init__(f"github api error {status}: {message}")
        self.status = status
        self.rate_limited = rate_limited
