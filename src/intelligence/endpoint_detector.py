import re
import json
from collections import defaultdict
from typing import List, Dict, Optional
from dataclasses import dataclass
from enum import Enum

@dataclass
class NetworkEndpoint:
    line_number: int
    content: str
    confidence: float
    category: str
    architecture: str
    additional_info: Optional[Dict] = None

class Architecture(Enum):
    X86 = "x86"
    X86_64 = "x86_64"
    ARM32 = "arm32"
    ARM64 = "arm64"
    WINDOWS = "windows"

class NetworkEndpointDetector:
    def __init__(self):
        self.detections = []
        self.context_window = 5
        self.confidence_threshold = 0.3
        self._init_linux_patterns()
        self._init_windows_patterns()
        self._init_arm_patterns()
        self._init_network_data_patterns()
        self._init_protocol_patterns()
        self._init_syscall_mappings()
        self._init_ipv6_patterns()  # Added IPv6 patterns initialization

    def _init_linux_patterns(self):
        self.linux_x86_patterns = [
            re.compile(r'\bint\s+0x80\b', re.IGNORECASE),
            re.compile(r'\bsyscall\b', re.IGNORECASE),
            re.compile(r'\bmov\s+(r|e)?ax,\s*41\b.*syscall', re.IGNORECASE | re.DOTALL),
            re.compile(r'\bmov\s+(r|e)?ax,\s*42\b.*syscall', re.IGNORECASE | re.DOTALL),
            re.compile(r'\bmov\s+(r|e)?ax,\s*43\b.*syscall', re.IGNORECASE | re.DOTALL),
            re.compile(r'\bmov\s+(r|e)?ax,\s*44\b.*syscall', re.IGNORECASE | re.DOTALL),
            re.compile(r'\bmov\s+(r|e)?ax,\s*45\b.*syscall', re.IGNORECASE | re.DOTALL),
            re.compile(r'\bmov\s+(e|r)?ax,\s*49\b.*syscall', re.IGNORECASE | re.DOTALL),
            re.compile(r'\bmov\s+(e|r)?ax,\s*50\b.*syscall', re.IGNORECASE | re.DOTALL),
            re.compile(r'\bmov\s+(r|e)?ax,\s*50\b.*syscall', re.IGNORECASE | re.DOTALL),
            re.compile(r'\bmov\s+(e|r)?ax,\s*102\b', re.IGNORECASE),
            re.compile(r'\bmov\s+(e|r)?bx,\s*[1-6]\b', re.IGNORECASE),
            re.compile(r'\bmov\s+(r|e)di,\s*(AF_INET|2)\b', re.IGNORECASE),
            re.compile(r'\bmov\s+(r|e)si,\s*(SOCK_STREAM|1)\b', re.IGNORECASE),
        ]
    def _init_windows_patterns(self):
        self.windows_patterns = [
            # --- Network-related APIs (WinSock, etc.)
            re.compile(r'\bcall\s+.*WSAStartup', re.IGNORECASE),
            re.compile(r'\bcall\s+.*WSACleanup', re.IGNORECASE),
            re.compile(r'\bcall\s+.*socket', re.IGNORECASE),
            re.compile(r'\bcall\s+.*connect', re.IGNORECASE),
            re.compile(r'\bcall\s+.*bind', re.IGNORECASE),
            re.compile(r'\bcall\s+.*listen', re.IGNORECASE),
            re.compile(r'\bcall\s+.*accept', re.IGNORECASE),
            re.compile(r'\bcall\s+.*send', re.IGNORECASE),
            re.compile(r'\bcall\s+.*recv', re.IGNORECASE),
            re.compile(r'\bcall\s+.*sendto', re.IGNORECASE),
            re.compile(r'\bcall\s+.*recvfrom', re.IGNORECASE),
            re.compile(r'\bcall\s+.*gethostbyname', re.IGNORECASE),
            re.compile(r'\bcall\s+.*getaddrinfo', re.IGNORECASE),
            # --- Dynamic loading patterns
            re.compile(r'\bcall\s+.*LoadLibrary.*', re.IGNORECASE),
            re.compile(r'\bcall\s+.*GetProcAddress', re.IGNORECASE),
            # --- Generic import call/jump (any imported API)
            re.compile(r'\b(call|jmp)\s+.*\[.*\]', re.IGNORECASE),
        ]
        # Additional patterns for general API detection
        self.file_api_patterns = [
            re.compile(r'\bcall\s+.*CreateFile(A|W)?', re.IGNORECASE),
            re.compile(r'\bcall\s+.*ReadFile', re.IGNORECASE),
            re.compile(r'\bcall\s+.*WriteFile', re.IGNORECASE),
            re.compile(r'\bcall\s+.*DeleteFile(A|W)?', re.IGNORECASE),
            re.compile(r'\bcall\s+.*CopyFile(A|W)?', re.IGNORECASE),
            re.compile(r'\bcall\s+.*MoveFile(A|W)?', re.IGNORECASE),
            re.compile(r'\bcall\s+.*SetFileAttributes', re.IGNORECASE),
        ]
        self.registry_api_patterns = [
            re.compile(r'\bcall\s+.*Reg(Open|Set|Get|Create|Delete|Query)[A-Za-z]*', re.IGNORECASE),
        ]
        self.process_api_patterns = [
            re.compile(r'\bcall\s+.*CreateProcess', re.IGNORECASE),
            re.compile(r'\bcall\s+.*OpenProcess', re.IGNORECASE),
            re.compile(r'\bcall\s+.*TerminateProcess', re.IGNORECASE),
        ]
        self.privilege_api_patterns = [
            re.compile(r'\bcall\s+.*AdjustTokenPrivileges', re.IGNORECASE),
            re.compile(r'\bcall\s+.*OpenProcessToken', re.IGNORECASE),
            re.compile(r'\bcall\s+.*LookupPrivilegeValue', re.IGNORECASE),
        ]
    def _init_arm_patterns(self):
        self.arm32_patterns = [
            re.compile(r'\bmov\s+r7,\s*#281\b.*svc\s+#0', re.IGNORECASE | re.DOTALL),
            re.compile(r'\bmov\s+r7,\s*#283\b.*svc\s+#0', re.IGNORECASE | re.DOTALL),
            re.compile(r'\bmov\s+r7,\s*#284\b.*svc\s+#0', re.IGNORECASE | re.DOTALL),
            re.compile(r'\bsvc\s+#0\b', re.IGNORECASE),
            re.compile(r'\bmovw\s+r7,\s*#281\b', re.IGNORECASE),
            re.compile(r'\bmovw\s+r7,\s*#283\b', re.IGNORECASE),
        ]
        self.arm64_patterns = [
            re.compile(r'\bmov\s+w8,\s*#198\b.*svc\s+#0', re.IGNORECASE | re.DOTALL),
            re.compile(r'\bmov\s+w8,\s*#203\b.*svc\s+#0', re.IGNORECASE | re.DOTALL),
            re.compile(r'\bmov\s+w8,\s*#202\b.*svc\s+#0', re.IGNORECASE | re.DOTALL),
            re.compile(r'\bsvc\s+#0\b', re.IGNORECASE),
        ]
    def _init_network_data_patterns(self):
        self.network_data_patterns = [
            re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'),
            re.compile(r'\b0x[0-9a-fA-F]{8}\b'),
            re.compile(r'\b(?:80|443|8080|8443|21|22|23|25|53|110|143|993|995|3306|5432|1433|8000|3000|5000)\b'),
            re.compile(r'\bhtons\s*\(\s*(\d+)\s*\)', re.IGNORECASE),
            re.compile(r'\bhtonl\s*\(\s*([0-9.]+)\s*\)', re.IGNORECASE),
            re.compile(r'\bntohs\s*\(\s*.*\s*\)', re.IGNORECASE),
            re.compile(r'\bntohl\s*\(\s*.*\s*\)', re.IGNORECASE),
            re.compile(r'\bAF_INET\b', re.IGNORECASE),
            re.compile(r'\bSOCK_STREAM\b', re.IGNORECASE),
            re.compile(r'\bSOCK_DGRAM\b', re.IGNORECASE),
            re.compile(r'\bstruct\s+sockaddr', re.IGNORECASE),
            re.compile(r'\bsockaddr_in\b', re.IGNORECASE),
        ]

    def _init_ipv6_patterns(self):
        """Initialize patterns for detecting IPv6 addresses in various formats."""
        self.ipv6_patterns = [
            re.compile(r'\b(?:([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|'           # 1:2:3:4:5:6:7:8
                     r'([0-9a-fA-F]{1,4}:){1,7}:|'                                # 1:: 1:2:3:4:5:6:7::
                     r'([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|'                # 1::8 1:2:3:4:5:6::8
                     r'([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|'         # 1::7:8 1:2:3:4:5::7:8
                     r'([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|'         # 1::6:7:8 1:2:3:4::6:7:8
                     r'([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|'         # 1::5:6:7:8 1:2:3::5:6:7:8
                     r'([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|'         # 1::4:5:6:7:8 1:2::4:5:6:7:8
                     r'[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|'              # 1::3:4:5:6:7:8
                     r':((:[0-9a-fA-F]{1,4}){1,7}|:)|'                            # ::2:3:4:5:6:7:8 ::8 ::
                     r'fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|'            # fe80::7:8%eth0 (link-local)
                     r'::(ffff(:0{1,4}){0,1}:){0,1}'                              # ::ffff:IPv4 (IPv4-mapped)
                     r'((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}'
                     r'(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|'
                     r'([0-9a-fA-F]{1,4}:){1,4}:'                                 # IPv4-embedded IPv6
                     r'((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}'
                     r'(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))\b', re.IGNORECASE),
            re.compile(r'\b([0-9a-fA-F]{1,4}:){5,7}[0-9a-fA-F]{1,4}\b', re.IGNORECASE),  # Full notation
            re.compile(r'\b([0-9a-fA-F]{1,4}:){1,7}:\b', re.IGNORECASE),                # Compressed end
            re.compile(r'\b::[0-9a-fA-F]{1,4}(:[0-9a-fA-F]{1,4}){0,6}\b', re.IGNORECASE), # Compressed start
            re.compile(r'\b([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b', re.IGNORECASE), # Compressed middle
            re.compile(r'\[([0-9a-fA-F:]{2,39})\]', re.IGNORECASE),
            re.compile(r'in6_addr\s*=\s*\{[^}]*\}', re.IGNORECASE),
            re.compile(r'sockaddr_in6\s*\{[^}]*\}', re.IGNORECASE),
            re.compile(r'inet6_addr\s*\([^\)]*\)', re.IGNORECASE),
            re.compile(r'\bAF_INET6\b', re.IGNORECASE),
            re.compile(r'\bPF_INET6\b', re.IGNORECASE),
            re.compile(r'\bINET6_ADDRSTRLEN\b', re.IGNORECASE),
            re.compile(r'\bs6_addr(?:\[\d+\]|\.\w+)\s*=\s*0x[0-9a-fA-F]{1,2}', re.IGNORECASE),
            re.compile(r'\bu6_addr(?:8|16|32)(?:\[\d+\]|\.\w+)\s*=\s*0x[0-9a-fA-F]{1,8}', re.IGNORECASE),
        ]
        self.ipv6_asm_patterns = [
            re.compile(r'(?:movw|mov\s+\w+,)\s*#?0x[0-9a-fA-F]{1,4}.*?(?:movw|mov\s+\w+,)\s*#?0x[0-9a-fA-F]{1,4}', re.IGNORECASE | re.DOTALL),
            re.compile(r'(?:mov|ldr|str)\s+\w+,\s*\[.*?in6_addr.*?\]', re.IGNORECASE),
            re.compile(r'(?:mov|ldr|str)\s+\w+,\s*\[.*?sockaddr_in6.*?\]', re.IGNORECASE),
            re.compile(r'\b(?:mov|ldr)\s+\w+,\s*#10\b.*?(?:socket|connect|bind)', re.IGNORECASE | re.DOTALL),
        ]
    def _init_protocol_patterns(self):
        self.protocol_patterns = [
            re.compile(r'\b(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|TRACE|PATCH)\s+/', re.IGNORECASE),
            re.compile(r'\bHTTP/[12]\.[01]\b', re.IGNORECASE),
            re.compile(r'\bUser-Agent:', re.IGNORECASE),
            re.compile(r'\bHost:', re.IGNORECASE),
            re.compile(r'\bContent-Type:', re.IGNORECASE),
            re.compile(r'\bContent-Length:', re.IGNORECASE),
            re.compile(r'\bSSL_CTX_new\b', re.IGNORECASE),
            re.compile(r'\bSSL_connect\b', re.IGNORECASE),
            re.compile(r'\bTLS.*init\b', re.IGNORECASE),
            re.compile(r'\b(?:USER|PASS|RETR|STOR|LIST|PWD|CWD)\s+', re.IGNORECASE),
            re.compile(r'\bgethostbyname\b', re.IGNORECASE),
            re.compile(r'\bgetaddrinfo\b', re.IGNORECASE),
            re.compile(r'\bres_query\b', re.IGNORECASE),
            re.compile(r'\bhttps?://[^\s<>"]+', re.IGNORECASE),
            re.compile(r'\bftp://[^\s<>"]+', re.IGNORECASE),
            re.compile(r'\b[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.[a-zA-Z]{2,}\b'),
        ]
    def _init_syscall_mappings(self):
        self.linux_syscalls = {
            41: "socket",
            42: "connect",
            43: "accept",
            44: "sendto",
            45: "recvfrom",
            46: "sendmsg",
            47: "recvmsg",
            49: "bind",
            50: "listen",
            51: "getsockname",
            52: "getpeername",
            53: "socketpair",
            54: "setsockopt",
            55: "getsockopt",
            102: "socketcall",
        }
        self.arm32_syscalls = {
            281: "socket",
            283: "connect",
            284: "accept",
            285: "getsockname",
            286: "getpeername",
            287: "socketpair",
            288: "send",
            289: "sendto",
            290: "recv",
            291: "recvfrom",
        }
        self.arm64_syscalls = {
            198: "socket",
            203: "connect",
            202: "accept",
            204: "getsockname",
            205: "getpeername",
            199: "bind",
            201: "listen",
        }

    def analyze_code(self, code_lines: List[str], file_type: str = "assembly") -> List[NetworkEndpoint]:
        self.detections = []
        patterns = (
            self.linux_x86_patterns + self.windows_patterns + self.arm32_patterns + self.arm64_patterns +
            self.file_api_patterns + self.registry_api_patterns + self.process_api_patterns + self.privilege_api_patterns +
            self.network_data_patterns + self.protocol_patterns +
            self.ipv6_patterns + self.ipv6_asm_patterns  # Include IPv6 patterns
        )
        for idx, line in enumerate(code_lines):
            for pat in patterns:
                m = pat.search(line)
                if m:
                    decoded = None
                    is_ipv6 = False
                    add_info = {"pattern": pat.pattern}

                    # Try to decode hex IPs (IPv4)
                    if pat.pattern == r'\b0x[0-9a-fA-F]{8}\b':
                        try:
                            val = int(m.group(), 16)
                            decoded = '.'.join(str((val >> (8 * i)) & 0xff) for i in range(4)[::-1])
                        except Exception:
                            decoded = None
                    # Try to identify IPv4 addresses
                    if pat.pattern.startswith(r'\b(?:(?:25[0-5]'):
                        decoded = m.group()
                    # Try to decode port numbers
                    if pat.pattern.startswith(r'\b(?:80|443|8080'):
                        decoded = m.group()
                    # Try to identify IPv6 addresses
                    for ipv6_pattern in getattr(self, 'ipv6_patterns', []):
                        if pat == ipv6_pattern:
                            is_ipv6 = True
                            decoded = m.group()
                            add_info["type"] = "IPv6"
                            break
                    # Detect IPv6 assembly patterns
                    for ipv6_asm_pattern in getattr(self, 'ipv6_asm_patterns', []):
                        if pat == ipv6_asm_pattern:
                            is_ipv6 = True
                            add_info["type"] = "IPv6_ASM"
                            # More complex logic could reconstruct the address
                    # Socket family identification for IPv6
                    if "AF_INET6" in line or "PF_INET6" in line:
                        add_info["socket_family"] = "IPv6"
                    if decoded:
                        add_info["decoded"] = decoded
                    self.detections.append(NetworkEndpoint(
                        line_number=idx,
                        content=line.strip(),
                        confidence=0.75 if is_ipv6 else 0.70,
                        category="IPv6 Network Data" if is_ipv6 else "Network Data",
                        architecture="unknown",
                        additional_info=add_info
                    ))
        self.detections.sort(key=lambda x: x.line_number)
        return self.detections

def format_endpoint_results(found, disassembly_lines=None):
    """
    Format detection results in a detailed, grouped, confidence-scored report (classic style).
    """
    if not found:
        return "No network endpoints or suspicious patterns detected."

    out = ["Detected Network Endpoints / Patterns:"]
    total = len(found)
    out.append(f"\nFound {total} potential network-related patterns\n")
    for i, d in enumerate(found, 1):
        out.append(f"\n[{i}] Line {d.line_number+1} (Confidence: {d.confidence:.2f}):")
        out.append(f"    {d.content}")
        if d.additional_info:
            out.append(f"    pattern: {d.additional_info.get('pattern','')}")
            if d.additional_info.get("decoded"):
                out.append(f"    decoded: {d.additional_info['decoded']}")
    return '\n'.join(out)


def detect_endpoints(disassembly_lines):
    """
    Wrapper for GUI integration. Returns a list of NetworkEndpoint objects for detected endpoints.
    """
    detector = NetworkEndpointDetector()
    if hasattr(detector, 'analyze_code'):
        results = detector.analyze_code(disassembly_lines, file_type="assembly")
        return results
    return []
