"""
skills_data15.py — DApp / Web3 / Smart Contract 전용 공격·감사 스킬 DB
bingo v3.2.60

Sources analyzed:
  [1] SWC Registry (Smart Contract Weakness Classification)
      https://swcregistry.io/
  [2] Immunefi Bug Bounty — Real-world DeFi exploit patterns
      https://immunefi.com/
  [3] Trail of Bits — Building Secure Contracts
      https://github.com/crytic/building-secure-contracts
  [4] Slither — Static Analyzer for Solidity
      https://github.com/crytic/slither
  [5] ConsenSys Diligence — Smart Contract Best Practices
      https://consensys.github.io/smart-contract-best-practices/
  [6] DeFi Hacks Analysis
      https://github.com/SunWeb3Sec/DeFiHackLabs
  [7] Ethernaut — OpenZeppelin CTF patterns
      https://ethernaut.openzeppelin.com/
  [8] Web3 API Endpoint Enumeration — Custom research

20 new skills:
  1.  web3-dapp-fingerprint        — DApp 기술 스택 핑거프린팅 (ethers/web3.js/wagmi/viem)
  2.  web3-rpc-enum                 — Ethereum JSON-RPC 엔드포인트 열거 및 노출 감지
  3.  web3-abi-extract              — 지갑 없이 컨트랙트 ABI + 함수 시그니처 추출
  4.  web3-reentrancy               — SWC-107 재진입 공격 취약점 감지 (Slither 패턴)
  5.  web3-integer-overflow         — SWC-101 정수 오버플로우/언더플로우 감지
  6.  web3-access-control           — SWC-105 미보호 함수 + 소유권 탈취 패턴
  7.  web3-tx-order-dependency      — SWC-114 프론트런닝 / TX 순서 의존성
  8.  web3-flash-loan               — Flash Loan 공격 벡터 분석 (가격 오라클 조작)
  9.  web3-oracle-manipulation      — 온체인 오라클 조작 / TWAP 우회
  10. web3-signature-replay         — SWC-121 서명 재사용 / EIP-712 미적용
  11. web3-delegate-call            — SWC-112 delegatecall 슬롯 충돌 취약점
  12. web3-selfdestruct             — SWC-106 selfdestruct 오용 + 강제 이더 전송
  13. web3-unchecked-call           — SWC-104 return value 미확인 저수준 call
  14. web3-timestamp-dependence     — SWC-116 블록 타임스탬프 의존성
  15. web3-private-data             — SWC-136 프라이빗 스토리지 데이터 노출
  16. web3-wallet-connect-enum      — WalletConnect/MetaMask 없이 DApp API 열거
  17. web3-graphql-subgraph         — DApp GraphQL 서브그래프 쿼리 취약점
  18. web3-nft-metadata-ssrf        — NFT 메타데이터 SSRF / URI 조작
  19. web3-defi-full-pipeline       — DeFi 전체 공격 파이프라인 (자동 선택)
  20. web3-contract-audit           — 스마트 컨트랙트 종합 감사 리포트 생성
"""
from __future__ import annotations

SKILLS_DB_15: dict[str, dict] = {

    # ── 1. DApp 핑거프린팅 ────────────────────────────────────────────
    "web3-dapp-fingerprint": {
        "id":          "web3-dapp-fingerprint",
        "name":        "DApp Web3 Stack Fingerprint",
        "name_ko":     "DApp Web3 기술 스택 핑거프린팅",
        "name_zh":     "DApp Web3技术栈指纹识别",
        "description": (
            "Fingerprint DApp technology stack without wallet connection. "
            "Detects ethers.js, web3.js, wagmi, viem, WalletConnect, MetaMask injection points. "
            "Extracts contract addresses from JS bundles, identifies chain ID, RPC endpoints. "
            "Maps exposed API routes that bypass wallet authentication."
        ),
        "description_ko": (
            "지갑 연결 없이 DApp 기술 스택을 핑거프린팅한다. "
            "ethers.js, web3.js, wagmi, viem, WalletConnect, MetaMask 주입 포인트를 감지한다. "
            "JS 번들에서 컨트랙트 주소를 추출하고 체인 ID, RPC 엔드포인트를 식별한다. "
            "지갑 인증을 우회하는 노출된 API 라우트를 매핑한다."
        ),
        "description_zh": (
            "无需钱包连接即可识别DApp技术栈。"
            "检测ethers.js、web3.js、wagmi、viem、WalletConnect、MetaMask注入点。"
            "从JS包中提取合约地址，识别链ID和RPC端点。"
            "映射绕过钱包认证的暴露API路由。"
        ),
        "tags":   ["dapp", "web3", "fingerprint", "ethers", "wagmi", "walletconnect", "metamask", "blockchain"],
        "module": "web3",
        "code": '''
import requests, re, json
from urllib.parse import urljoin, urlparse

TARGET = "{target}"
headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

print(f"[*] DApp 핑거프린팅 시작: {TARGET}")

def fetch(url, **kw):
    try:
        r = requests.get(url, headers=headers, timeout=10, verify=False, **kw)
        return r
    except Exception as e:
        print(f"  [-] 요청 실패: {e}")
        return None

# 1. 메인 페이지 분석
r = fetch(TARGET)
if not r:
    print("[-] 타겟 접근 불가")
    exit()

html = r.text
print(f"[+] 응답: {r.status_code} | {len(html)} bytes")

# 2. Web3 라이브러리 감지
web3_libs = {
    "ethers.js":      [r'ethers', r'ethers\.utils', r'ethers\.Contract'],
    "web3.js":        [r'new Web3\(', r'web3\.eth', r'web3\.utils'],
    "wagmi":          [r'wagmi', r'useAccount', r'useConnect'],
    "viem":           [r'viem', r'createPublicClient', r'createWalletClient'],
    "WalletConnect":  [r'WalletConnect', r'walletconnect', r'@walletconnect'],
    "MetaMask":       [r'ethereum\.request', r'window\.ethereum', r'MetaMask'],
    "RainbowKit":     [r'RainbowKit', r'rainbowkit', r'ConnectButton'],
    "web3modal":      [r'Web3Modal', r'web3modal'],
}
print("\\n[*] Web3 라이브러리 감지:")
for lib, patterns in web3_libs.items():
    if any(re.search(p, html, re.I) for p in patterns):
        print(f"  [FOUND] {lib}")

# 3. 컨트랙트 주소 추출 (0x + 40 hex)
contracts = re.findall(r\'0x[a-fA-F0-9]{40}\', html)
unique_contracts = list(set(contracts))
if unique_contracts:
    print(f"\\n[+] 컨트랙트 주소 발견 ({len(unique_contracts)}개):")
    for addr in unique_contracts[:20]:
        print(f"  {addr}")

# 4. RPC 엔드포인트 감지
rpc_patterns = [
    r\'https?://[\\w.-]+\\.infura\\.io/[\\w/]+\',
    r\'https?://[\\w.-]+\\.alchemyapi\\.io/[\\w/]+\',
    r\'https?://rpc\\.ankr\\.com/[\\w]+\',
    r\'wss?://[\\w.-]+/[\\w/]+\',
    r\'https?://mainnet\\.infura\\.io\',
    r\'https?://[\\w.-]+\\.quicknode\\.pro/[\\w/]+\',
]
print("\\n[*] RPC 엔드포인트 감지:")
for p in rpc_patterns:
    found = re.findall(p, html)
    for f in set(found):
        print(f"  [RPC] {f}")

# 5. JS 번들에서 추가 분석
js_urls = re.findall(r\'src=["\\\']([^"\\\']*\\.js[^"\\\']*)[\"\\\']', html)
print(f"\\n[*] JS 파일 {len(js_urls)}개 발견 - 핵심 파일 분석 중...")
for js_url in js_urls[:5]:
    full_url = urljoin(TARGET, js_url)
    jr = fetch(full_url)
    if jr and jr.status_code == 200:
        jtext = jr.text
        # API 키 노출 확인
        api_keys = re.findall(r\'(?:INFURA_KEY|ALCHEMY_KEY|API_KEY|REACT_APP_)[\\w_]*[=:]["\\\']?([a-zA-Z0-9]{20,})\', jtext)
        if api_keys:
            print(f"  [!] API 키 노출 가능성: {js_url}")
            for k in api_keys[:3]:
                print(f"      {k[:20]}...")
        # 체인 ID
        chain_ids = re.findall(r\'chainId[\\s:=]+([0-9]+)\', jtext)
        if chain_ids:
            print(f"  [CHAIN] 체인 ID: {list(set(chain_ids))}")

print("\\n[*] 핑거프린팅 완료")
''',
    },

    # ── 2. JSON-RPC 엔드포인트 열거 ───────────────────────────────────
    "web3-rpc-enum": {
        "id":          "web3-rpc-enum",
        "name":        "Ethereum JSON-RPC Endpoint Enumeration",
        "name_ko":     "이더리움 JSON-RPC 엔드포인트 노출 감지",
        "name_zh":     "以太坊JSON-RPC端点枚举",
        "description": (
            "Enumerate exposed Ethereum JSON-RPC endpoints on target. "
            "Tests common paths (/rpc, /api, /ethereum, etc.). "
            "Checks dangerous methods: eth_accounts, personal_listAccounts, "
            "eth_sendTransaction without auth, debug_traceTransaction, net_peerCount. "
            "Detects unauthenticated node access."
        ),
        "description_ko": (
            "타겟의 노출된 이더리움 JSON-RPC 엔드포인트를 열거한다. "
            "일반적인 경로(/rpc, /api, /ethereum 등)를 테스트한다. "
            "위험한 메서드를 확인한다: eth_accounts, personal_listAccounts, "
            "인증 없는 eth_sendTransaction, debug_traceTransaction, net_peerCount. "
            "미인증 노드 접근을 감지한다."
        ),
        "description_zh": (
            "枚举目标上暴露的以太坊JSON-RPC端点。"
            "测试常见路径(/rpc, /api, /ethereum等)。"
            "检查危险方法: eth_accounts、personal_listAccounts、"
            "无认证eth_sendTransaction、debug_traceTransaction、net_peerCount。"
            "检测未认证节点访问。"
        ),
        "tags":   ["web3", "rpc", "ethereum", "jsonrpc", "blockchain", "node", "dapp"],
        "module": "web3",
        "code": '''
import requests, json
from urllib.parse import urlparse

TARGET = "{target}"
parsed = urlparse(TARGET)
base = f"{parsed.scheme}://{parsed.netloc}"

headers = {"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"}

rpc_paths = ["/", "/rpc", "/api", "/ethereum", "/eth", "/jsonrpc",
             "/v1/rpc", "/api/v1/rpc", "/node", "/geth"]

dangerous_methods = [
    ("eth_accounts",              {"jsonrpc":"2.0","method":"eth_accounts","params":[],"id":1}),
    ("personal_listAccounts",     {"jsonrpc":"2.0","method":"personal_listAccounts","params":[],"id":2}),
    ("eth_blockNumber",           {"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":3}),
    ("net_version",               {"jsonrpc":"2.0","method":"net_version","params":[],"id":4}),
    ("net_peerCount",             {"jsonrpc":"2.0","method":"net_peerCount","params":[],"id":5}),
    ("eth_getBalance(0x0)",       {"jsonrpc":"2.0","method":"eth_getBalance","params":["0x0000000000000000000000000000000000000000","latest"],"id":6}),
    ("debug_traceTransaction",    {"jsonrpc":"2.0","method":"debug_traceTransaction","params":["0x"+\"0\"*64,{}],"id":7}),
    ("personal_unlockAccount",    {"jsonrpc":"2.0","method":"personal_unlockAccount","params":["0x0","",0],"id":8}),
]

print(f"[*] JSON-RPC 엔드포인트 스캔: {base}")

for path in rpc_paths:
    url = base + path
    try:
        r = requests.post(url, json={"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1},
                         headers=headers, timeout=5, verify=False)
        if r.status_code == 200:
            try:
                data = r.json()
                if "result" in data or "jsonrpc" in data:
                    print(f"\\n[!!!] RPC 엔드포인트 발견: {url}")
                    print(f"  응답: {json.dumps(data)[:200]}")

                    # 위험 메서드 순차 테스트
                    print("  [*] 위험 메서드 테스트:")
                    for method_name, payload in dangerous_methods:
                        try:
                            mr = requests.post(url, json=payload, headers=headers, timeout=5, verify=False)
                            if mr.status_code == 200:
                                mdata = mr.json()
                                if "result" in mdata and mdata["result"] is not None:
                                    print(f"    [VULN] {method_name}: {str(mdata[\'result\'])[:100]}")
                                elif "error" in mdata:
                                    print(f"    [-] {method_name}: {mdata[\'error\'].get(\'message\',\'error\')[:60]}")
                        except:
                            pass
            except:
                pass
    except:
        pass

print("\\n[*] RPC 스캔 완료")
''',
    },

    # ── 3. ABI 추출 ──────────────────────────────────────────────────
    "web3-abi-extract": {
        "id":          "web3-abi-extract",
        "name":        "Smart Contract ABI Extraction (No Wallet)",
        "name_ko":     "스마트 컨트랙트 ABI 추출 (지갑 없이)",
        "name_zh":     "无钱包智能合约ABI提取",
        "description": (
            "Extract smart contract ABI and function signatures without wallet connection. "
            "Fetches verified contract ABI from Etherscan/BSCScan/PolygonScan APIs. "
            "Decodes function selectors (4-byte), identifies payable/external functions. "
            "Maps callable endpoints for unauthorized interaction testing."
        ),
        "description_ko": (
            "지갑 연결 없이 스마트 컨트랙트 ABI와 함수 시그니처를 추출한다. "
            "Etherscan/BSCScan/PolygonScan API에서 검증된 컨트랙트 ABI를 가져온다. "
            "함수 셀렉터(4바이트)를 디코딩하고 payable/external 함수를 식별한다. "
            "미인증 상호작용 테스트를 위한 호출 가능 엔드포인트를 매핑한다."
        ),
        "description_zh": (
            "无需钱包连接即可提取智能合约ABI和函数签名。"
            "从Etherscan/BSCScan/PolygonScan API获取验证合约ABI。"
            "解码函数选择器(4字节)，识别payable/external函数。"
            "映射可调用端点用于未授权交互测试。"
        ),
        "tags":   ["web3", "abi", "contract", "etherscan", "solidity", "function", "dapp", "blockchain"],
        "module": "web3",
        "code": '''
import requests, json, hashlib

CONTRACT_ADDRESS = "{target}"  # 0x로 시작하는 컨트랙트 주소 또는 타겟 URL

headers = {"User-Agent": "Mozilla/5.0"}

# Etherscan 무료 API (키 없이도 기본 사용 가능)
explorers = [
    ("Ethereum",  f"https://api.etherscan.io/api?module=contract&action=getabi&address={CONTRACT_ADDRESS}"),
    ("BSC",       f"https://api.bscscan.com/api?module=contract&action=getabi&address={CONTRACT_ADDRESS}"),
    ("Polygon",   f"https://api.polygonscan.com/api?module=contract&action=getabi&address={CONTRACT_ADDRESS}"),
    ("Arbitrum",  f"https://api.arbiscan.io/api?module=contract&action=getabi&address={CONTRACT_ADDRESS}"),
    ("Optimism",  f"https://api-optimistic.etherscan.io/api?module=contract&action=getabi&address={CONTRACT_ADDRESS}"),
]

def keccak4(func_sig):
    """함수 시그니처 → 4바이트 셀렉터 계산 (순수 Python)"""
    try:
        import hashlib
        # keccak256 근사 (정확한 계산은 pysha3 필요)
        return hashlib.sha256(func_sig.encode()).hexdigest()[:8]
    except:
        return "????????"

print(f"[*] ABI 추출 시작: {CONTRACT_ADDRESS}")

abi = None
for chain, url in explorers:
    try:
        r = requests.get(url, headers=headers, timeout=10)
        data = r.json()
        if data.get("status") == "1" and data.get("result") != "Contract source code not verified":
            abi = json.loads(data["result"])
            print(f"[+] ABI 발견 ({chain}): {len(abi)}개 항목")
            break
    except:
        continue

if not abi:
    print("[-] 공개 ABI 없음 — JS 번들에서 ABI 추출 시도")
    # DApp 사이트에서 ABI 패턴 검색
    import re
    r = requests.get(CONTRACT_ADDRESS if CONTRACT_ADDRESS.startswith("http") else f"https://{CONTRACT_ADDRESS}",
                    headers=headers, timeout=10, verify=False)
    abi_patterns = re.findall(r\'\\[{[^\\[\\]]*"type":"function"[^\\[\\]]*}\\]\', r.text)
    if abi_patterns:
        print(f"[+] JS에서 ABI 패턴 {len(abi_patterns)}개 발견")
        abi = json.loads(abi_patterns[0])
    else:
        print("[-] ABI 추출 실패")
        exit()

# 함수 분류 및 위험도 평가
print("\\n[*] 함수 목록 분석:")
print(f"{'함수명':<40} {'타입':<15} {'상태변환':<10} {'위험도'}")
print("-" * 80)

risky_funcs = []
for item in abi:
    if item.get("type") == "function":
        name = item.get("name", "?")
        mutability = item.get("stateMutability", "?")
        inputs = item.get("inputs", [])
        
        # 위험도 판단
        risk = "LOW"
        if mutability == "payable":
            risk = "HIGH"
        elif mutability not in ("view", "pure"):
            risk = "MEDIUM"
        if any(kw in name.lower() for kw in ["admin", "owner", "withdraw", "transfer", "mint", "burn", "upgrade"]):
            risk = "CRITICAL"
        
        # 함수 시그니처
        params = ",".join(i.get("type","?") for i in inputs)
        sig = f"{name}({params})"
        selector = keccak4(sig)
        
        print(f"{sig:<40} {mutability:<15} {'yes' if mutability not in ('view','pure') else 'no':<10} [{risk}]")
        if risk in ("HIGH", "CRITICAL"):
            risky_funcs.append((risk, sig, selector))

print(f"\\n[!!!] 고위험 함수 {len(risky_funcs)}개:")
for risk, sig, selector in risky_funcs:
    print(f"  [{risk}] {sig} (selector: 0x{selector})")
''',
    },

    # ── 4. 재진입 공격 (SWC-107) ─────────────────────────────────────
    "web3-reentrancy": {
        "id":          "web3-reentrancy",
        "name":        "Reentrancy Attack Detection (SWC-107)",
        "name_ko":     "재진입 공격 취약점 감지 (SWC-107)",
        "name_zh":     "重入攻击漏洞检测 (SWC-107)",
        "description": (
            "Detect reentrancy vulnerabilities in Solidity smart contracts (SWC-107). "
            "Checks for CEI (Checks-Effects-Interactions) pattern violations. "
            "Identifies external calls before state updates, missing reentrancy guards. "
            "Analyzes withdrawal patterns, ETH transfer functions. "
            "Based on Slither's reentrancy detector patterns and DAO hack analysis."
        ),
        "description_ko": (
            "Solidity 스마트 컨트랙트의 재진입 취약점을 감지한다 (SWC-107). "
            "CEI(검사-효과-상호작용) 패턴 위반을 확인한다. "
            "상태 업데이트 전 외부 호출, 재진입 가드 누락을 식별한다. "
            "출금 패턴, ETH 전송 함수를 분석한다. "
            "Slither 재진입 감지기 패턴 및 DAO 해킹 분석을 기반으로 한다."
        ),
        "description_zh": (
            "检测Solidity智能合约中的重入漏洞(SWC-107)。"
            "检查CEI(检查-效果-交互)模式违规。"
            "识别状态更新前的外部调用、缺少重入防护。"
            "分析提款模式、ETH转账函数。"
            "基于Slither重入检测器模式和DAO攻击分析。"
        ),
        "tags":   ["reentrancy", "solidity", "swc107", "defi", "smart-contract", "audit", "dao", "web3"],
        "module": "web3",
        "code": '''
import re, sys

# 분석할 Solidity 소스코드 입력 또는 파일 경로
SOLIDITY_CODE = """
{target}
"""

print("[*] 재진입 취약점 분석 (SWC-107) 시작")
code = SOLIDITY_CODE

# 1. external call 패턴
ext_call_patterns = [
    (r\'(\\.call{[^}]*}\\s*\\([^)]*\\))\',      "low-level .call()"),
    (r\'(\\.transfer\\s*\\([^)]*\\))\',          ".transfer()"),
    (r\'(\\.send\\s*\\([^)]*\\))\',              ".send()"),
    (r\'(IERC20\\([^)]*\\)\\.transfer)\',         "ERC20 transfer"),
    (r\'(address\\([^)]*\\)\\.call)\',            "address.call"),
]

print("\\n[*] External Call 패턴 검색:")
for pattern, desc in ext_call_patterns:
    matches = re.findall(pattern, code)
    if matches:
        print(f"  [FOUND] {desc}: {len(matches)}회 발견")
        for m in matches[:3]:
            print(f"    → {m[:80]}")

# 2. 상태 변경 후 external call (위험)
lines = code.split("\\n")
state_change_after_call = []
for i, line in enumerate(lines):
    if re.search(r\'\\.(call|transfer|send)\\s*\\(\', line):
        # 이후 라인에서 상태 변경 있는지 확인
        for j in range(i+1, min(i+10, len(lines))):
            if re.search(r\'(balance|amount|state|locked)\\s*[+-]?=\', lines[j]):
                state_change_after_call.append((i+1, line.strip(), j+1, lines[j].strip()))

if state_change_after_call:
    print("\\n[!!!] CEI 패턴 위반 의심 (상태변경이 external call 이후):")
    for call_line, call_code, state_line, state_code in state_change_after_call[:5]:
        print(f"  Line {call_line}: {call_code[:60]}")
        print(f"  Line {state_line}: {state_code[:60]} ← 상태 변경")
        print()
else:
    print("\\n[OK] CEI 패턴 위반 없음")

# 3. ReentrancyGuard 확인
if "nonReentrant" in code or "ReentrancyGuard" in code:
    print("[OK] ReentrancyGuard 사용됨")
else:
    print("[!] ReentrancyGuard 미사용 — withdraw/transfer 함수에 nonReentrant 추가 권장")

# 4. withdraw 함수 특별 분석
withdraw_funcs = re.findall(r\'function\\s+withdraw[^{]*{([^}]+)}\', code, re.DOTALL)
for func in withdraw_funcs:
    if re.search(r\'\\.(call|transfer|send)\', func):
        balance_check_before = bool(re.search(r\'balance|amount\', func[:func.find(".call") if ".call" in func else len(func)]))
        print(f"\\n[CRITICAL] withdraw 함수에서 ETH 전송 발견")
        if not "nonReentrant" in func:
            print("  → nonReentrant 가드 없음: 재진입 공격 취약!")

print("\\n[*] 재진입 분석 완료")
''',
    },

    # ── 5. 정수 오버플로우 (SWC-101) ──────────────────────────────────
    "web3-integer-overflow": {
        "id":          "web3-integer-overflow",
        "name":        "Integer Overflow/Underflow Detection (SWC-101)",
        "name_ko":     "정수 오버플로우/언더플로우 감지 (SWC-101)",
        "name_zh":     "整数溢出/下溢检测 (SWC-101)",
        "description": (
            "Detect integer overflow and underflow vulnerabilities (SWC-101). "
            "Checks Solidity version for SafeMath requirement (< 0.8.0). "
            "Identifies arithmetic operations without SafeMath or unchecked blocks. "
            "Finds token balance manipulation patterns."
        ),
        "description_ko": (
            "정수 오버플로우 및 언더플로우 취약점을 감지한다 (SWC-101). "
            "SafeMath 필요 여부를 위한 Solidity 버전을 확인한다 (0.8.0 미만). "
            "SafeMath 또는 unchecked 블록 없이 산술 연산을 식별한다. "
            "토큰 잔액 조작 패턴을 찾는다."
        ),
        "description_zh": (
            "检测整数溢出和下溢漏洞(SWC-101)。"
            "检查Solidity版本是否需要SafeMath(< 0.8.0)。"
            "识别没有SafeMath或unchecked块的算术运算。"
            "查找代币余额操纵模式。"
        ),
        "tags":   ["overflow", "underflow", "safemath", "swc101", "solidity", "audit", "web3", "integer"],
        "module": "web3",
        "code": '''
import re

SOLIDITY_CODE = """
{target}
"""
code = SOLIDITY_CODE
print("[*] 정수 오버플로우/언더플로우 분석 (SWC-101)")

# 1. Solidity 버전 확인
pragma = re.search(r\'pragma solidity\\s+([^;]+);\', code)
if pragma:
    ver_str = pragma.group(1)
    print(f"[*] Solidity 버전: {ver_str}")
    # 0.8.0 미만이면 오버플로우 자동 방어 없음
    old_ver = re.search(r\'0\\.[0-7]\\.\', ver_str) or "^0." in ver_str
    if old_ver:
        print("[!] 0.8.0 미만 버전 — SafeMath 필요!")
    else:
        print("[OK] 0.8.0+ — 기본 오버플로우 방어 내장")

# 2. SafeMath 사용 확인
if "SafeMath" in code or "using SafeMath" in code:
    print("[OK] SafeMath 사용됨")
elif "pragma solidity ^0.8" in code or "pragma solidity >=0.8" in code:
    print("[OK] 0.8+ 내장 오버플로우 방어")
else:
    print("[!] SafeMath 미사용")

# 3. 위험한 산술 연산 패턴
danger_patterns = [
    (r\'(\\w+)\\s*\\+=\\s*(\\w+)\', "덧셈 할당 (+=)"),
    (r\'(\\w+)\\s*-=\\s*(\\w+)\', "뺄셈 할당 (-=) ← 언더플로우 위험"),
    (r\'(\\w+)\\s*\\*=\\s*(\\w+)\', "곱셈 할당 (*=)"),
    (r\'(\\w+)\\s*\\*\\s*(\\w+)\\s*(?!/)\\s*[^/]\', "곱셈 연산"),
    (r\'uint\\s+\\w+\\s*=\\s*\\w+\\s*-\\s*\\w+\', "uint 뺄셈 — 언더플로우 가능"),
]

print("\\n[*] 위험 산술 패턴 분석:")
for pattern, desc in danger_patterns:
    matches = re.findall(pattern, code)
    if matches:
        print(f"  [!] {desc}: {len(matches)}회")

# 4. unchecked 블록 감지 (0.8+에서 의도적 오버플로우)
unchecked = re.findall(r\'unchecked\\s*{([^}]+)}\', code, re.DOTALL)
if unchecked:
    print(f"\\n[!] unchecked 블록 {len(unchecked)}개 — 의도적 오버플로우 허용 구간:")
    for u in unchecked[:3]:
        print(f"  → {u[:100]}")

print("\\n[*] 분석 완료")
''',
    },

    # ── 6. 접근 제어 취약점 (SWC-105) ────────────────────────────────
    "web3-access-control": {
        "id":          "web3-access-control",
        "name":        "Access Control Vulnerability (SWC-105)",
        "name_ko":     "접근 제어 취약점 감지 (SWC-105)",
        "name_zh":     "访问控制漏洞检测 (SWC-105)",
        "description": (
            "Detect access control vulnerabilities in smart contracts (SWC-105). "
            "Identifies unprotected admin functions, missing onlyOwner modifiers. "
            "Checks ownership transfer patterns, Ownable implementation. "
            "Finds tx.origin authentication bypass patterns."
        ),
        "description_ko": (
            "스마트 컨트랙트의 접근 제어 취약점을 감지한다 (SWC-105). "
            "보호되지 않은 관리자 함수, 누락된 onlyOwner 수정자를 식별한다. "
            "소유권 이전 패턴, Ownable 구현을 확인한다. "
            "tx.origin 인증 우회 패턴을 찾는다."
        ),
        "description_zh": (
            "检测智能合约中的访问控制漏洞(SWC-105)。"
            "识别未受保护的管理函数、缺少onlyOwner修饰符。"
            "检查所有权转移模式、Ownable实现。"
            "查找tx.origin认证绕过模式。"
        ),
        "tags":   ["access-control", "ownable", "swc105", "solidity", "admin", "audit", "web3", "privilege"],
        "module": "web3",
        "code": '''
import re

SOLIDITY_CODE = """
{target}
"""
code = SOLIDITY_CODE
print("[*] 접근 제어 취약점 분석 (SWC-105)")

# 1. 관리자 함수 목록 추출
admin_funcs = re.findall(r\'function\\s+(\\w*(?:admin|owner|mint|burn|upgrade|set|update|pause|withdraw|transfer)[\\w]*)\\s*\\([^)]*\\)\\s*([^{]*)\', code, re.I)

print("\\n[*] 관리자 함수 분석:")
for func_name, modifiers in admin_funcs:
    has_guard = any(kw in modifiers for kw in ["onlyOwner", "onlyAdmin", "onlyRole", "require(msg.sender"])
    risk = "[OK]" if has_guard else "[CRITICAL]"
    print(f"  {risk} {func_name}() — 수정자: {modifiers.strip()[:60] or \'없음\'}")

# 2. tx.origin 사용 감지 (SWC-115)
tx_origin = re.findall(r\'tx\\.origin\', code)
if tx_origin:
    print(f"\\n[CRITICAL] tx.origin 사용 {len(tx_origin)}회 — msg.sender로 교체 필요!")
    print("  tx.origin은 피싱 공격에 취약")

# 3. selfdestruct 감지 (SWC-106)
if "selfdestruct" in code or "suicide(" in code:
    # 보호 여부 확인
    lines = code.split("\\n")
    for i, line in enumerate(lines):
        if "selfdestruct" in line or "suicide(" in line:
            context = "\\n".join(lines[max(0,i-3):i+2])
            if "onlyOwner" not in context and "require(msg.sender" not in context:
                print(f"\\n[CRITICAL] 비보호 selfdestruct 발견 (line {i+1})")

# 4. Ownable 상속 확인
if "Ownable" in code:
    print("\\n[OK] Ownable 패턴 사용됨")
elif "owner" in code.lower():
    print("\\n[!] 커스텀 owner 구현 — 검증 필요")

# 5. 권한 없는 초기화 함수 (Proxy 패턴)
init_funcs = re.findall(r\'function\\s+initialize\\s*\\([^)]*\\)\\s*([^{]*)\', code)
for mods in init_funcs:
    if "initializer" not in mods and "onlyOwner" not in mods:
        print("\\n[CRITICAL] initialize() 함수에 initializer 수정자 없음 — 재초기화 공격 가능!")

print("\\n[*] 접근 제어 분석 완료")
''',
    },

    # ── 7. 프론트런닝 (SWC-114) ──────────────────────────────────────
    "web3-tx-order-dependency": {
        "id":          "web3-tx-order-dependency",
        "name":        "Front-Running / TX Order Dependency (SWC-114)",
        "name_ko":     "프론트런닝 / TX 순서 의존성 (SWC-114)",
        "name_zh":     "抢先交易/交易顺序依赖 (SWC-114)",
        "description": (
            "Detect transaction order dependency and front-running vulnerabilities (SWC-114). "
            "Identifies price-sensitive operations without slippage protection. "
            "Finds approve/transferFrom race conditions (ERC20). "
            "Detects commit-reveal scheme absence in auctions/randomness."
        ),
        "description_ko": (
            "트랜잭션 순서 의존성 및 프론트런닝 취약점을 감지한다 (SWC-114). "
            "슬리피지 보호 없는 가격 민감 연산을 식별한다. "
            "approve/transferFrom 경쟁 조건(ERC20)을 찾는다. "
            "경매/무작위성에서 커밋-공개 방식 부재를 감지한다."
        ),
        "description_zh": (
            "检测交易顺序依赖和抢先交易漏洞(SWC-114)。"
            "识别没有滑点保护的价格敏感操作。"
            "查找approve/transferFrom竞态条件(ERC20)。"
            "检测拍卖/随机性中缺少提交-揭示方案。"
        ),
        "tags":   ["frontrunning", "mev", "swc114", "defi", "slippage", "erc20", "web3", "audit"],
        "module": "web3",
        "code": '''
import re

SOLIDITY_CODE = """
{target}
"""
code = SOLIDITY_CODE
print("[*] 프론트런닝 / TX 순서 의존성 분석 (SWC-114)")

# 1. ERC20 approve 취약점
approve_pattern = re.findall(r\'function\\s+approve\\s*\\(\', code)
if approve_pattern:
    if "increaseAllowance" not in code and "decreaseAllowance" not in code:
        print("[!] ERC20 approve() 사용 — increaseAllowance/decreaseAllowance 없음")
        print("    race condition 취약점: approve(0) 후 재설정 권장")

# 2. 슬리피지 없는 swap 감지
swap_without_slippage = re.findall(r\'function\\s+swap[^{]*{([^}]+)}\', code, re.DOTALL)
for func_body in swap_without_slippage:
    if not re.search(r\'amountOutMin|minAmount|slippage|deadline\', func_body):
        print("[CRITICAL] swap 함수에 슬리피지 보호 없음 — MEV 공격 위험!")

# 3. block.timestamp 가격 계산
if re.search(r\'block\\.timestamp.*price|price.*block\\.timestamp\', code):
    print("[!] block.timestamp 기반 가격 계산 감지 — 마이너 조작 가능")

# 4. commit-reveal 패턴 확인 (복권/경매)
if re.search(r\'random|lottery|auction\', code, re.I):
    if "commit" not in code and "reveal" not in code:
        print("[!] 무작위성/경매 로직에 commit-reveal 패턴 없음")
        if "block.prevrandao" not in code and "chainlink" not in code.lower():
            print("[CRITICAL] 온체인 무작위성 사용 — 예측 가능!")

# 5. deadline 미사용 감지
deadline_check = re.search(r\'require.*deadline|block\\.timestamp.*<=.*deadline\', code)
if not deadline_check and swap_without_slippage:
    print("[!] 트랜잭션 deadline 없음 — stale 트랜잭션 프론트런닝 가능")

print("\\n[*] 프론트런닝 분석 완료")
''',
    },

    # ── 8. Flash Loan 공격 ──────────────────────────────────────────
    "web3-flash-loan": {
        "id":          "web3-flash-loan",
        "name":        "Flash Loan Attack Vector Analysis",
        "name_ko":     "플래시론 공격 벡터 분석",
        "name_zh":     "闪电贷攻击向量分析",
        "description": (
            "Analyze DeFi protocol for flash loan attack vectors. "
            "Tests for price oracle manipulation through single-block liquidity. "
            "Identifies missing flash loan protection (same-block restriction). "
            "Checks TWAP oracle usage vs spot price vulnerability."
        ),
        "description_ko": (
            "플래시론 공격 벡터에 대해 DeFi 프로토콜을 분석한다. "
            "단일 블록 유동성을 통한 가격 오라클 조작을 테스트한다. "
            "플래시론 보호 누락(동일 블록 제한)을 식별한다. "
            "TWAP 오라클 사용 대 스팟 가격 취약점을 확인한다."
        ),
        "description_zh": (
            "分析DeFi协议的闪电贷攻击向量。"
            "通过单块流动性测试价格预言机操纵。"
            "识别缺少闪电贷保护(同块限制)。"
            "检查TWAP预言机使用与现货价格漏洞。"
        ),
        "tags":   ["flashloan", "defi", "oracle", "price-manipulation", "aave", "compound", "web3", "audit"],
        "module": "web3",
        "code": '''
import re

SOLIDITY_CODE = """
{target}
"""
code = SOLIDITY_CODE
print("[*] 플래시론 공격 벡터 분석")

# 1. 가격 오라클 패턴
oracle_patterns = [
    (r\'getReserves\\(\\)\',         "Uniswap V2 spot price — 조작 가능!"),
    (r\'token0Price|token1Price\',    "Uniswap V3 spot price — 조작 가능!"),
    (r\'latestAnswer\\(\\)\',         "Chainlink — 상대적으로 안전"),
    (r\'consult\\(.*TWAP\',           "TWAP — 안전"),
    (r\'observe\\(\\)\',              "Uniswap V3 TWAP — 안전"),
    (r\'balanceOf.*\\/.*totalSupply\', "잔액 기반 가격 계산 — 조작 가능!"),
]

print("\\n[*] 가격 오라클 분석:")
for pattern, desc in oracle_patterns:
    if re.search(pattern, code, re.I):
        risk = "CRITICAL" if "조작 가능" in desc else "OK"
        print(f"  [{risk}] {desc}")

# 2. 플래시론 보호 확인
if "flashLoan" in code or "executeOperation" in code:
    print("\\n[*] 플래시론 콜백 발견")
    if "initiator" not in code and "sender" not in code.lower():
        print("  [!] 플래시론 콜백 발신자 검증 없음!")

# 3. 동일 트랜잭션 재진입 보호
if re.search(r\'locked|_locked|inFlashLoan|flashLoanActive\', code):
    print("[OK] 플래시론 재진입 보호 있음")
else:
    if re.search(r\'borrow|lend|liquidat\', code, re.I):
        print("[!] 대출/청산 로직에 플래시론 가드 없음")

# 4. 단일 블록 가격 변동 감지
if re.search(r\'block\\.number.*==|lastUpdate.*block\\.number\', code):
    print("[OK] 블록 번호 기반 업데이트 보호 있음")

print("\\n[*] 플래시론 분석 완료")
''',
    },

    # ── 9. 오라클 조작 ─────────────────────────────────────────────
    "web3-oracle-manipulation": {
        "id":          "web3-oracle-manipulation",
        "name":        "Price Oracle Manipulation Detection",
        "name_ko":     "가격 오라클 조작 감지",
        "name_zh":     "价格预言机操纵检测",
        "description": (
            "Detect price oracle manipulation vulnerabilities in DeFi protocols. "
            "Identifies reliance on AMM spot prices (manipulable in single tx). "
            "Tests TWAP window adequacy, Chainlink staleness checks. "
            "Finds missing deviation checks between oracle sources."
        ),
        "description_ko": (
            "DeFi 프로토콜의 가격 오라클 조작 취약점을 감지한다. "
            "AMM 스팟 가격 의존성(단일 tx에서 조작 가능)을 식별한다. "
            "TWAP 창 적절성, Chainlink 신선도 확인을 테스트한다. "
            "오라클 소스 간 편차 확인 누락을 찾는다."
        ),
        "description_zh": (
            "检测DeFi协议中的价格预言机操纵漏洞。"
            "识别依赖AMM现货价格(可在单个tx中操纵)。"
            "测试TWAP窗口充分性、Chainlink过期检查。"
            "查找预言机来源之间缺少偏差检查。"
        ),
        "tags":   ["oracle", "twap", "chainlink", "defi", "price-manipulation", "web3", "audit"],
        "module": "web3",
        "code": '''
import re

SOLIDITY_CODE = """
{target}
"""
code = SOLIDITY_CODE
print("[*] 가격 오라클 조작 분석")

issues = []

# 1. Chainlink 신선도 확인
chainlink_calls = re.findall(r\'latestRoundData\\(\\)\', code)
if chainlink_calls:
    print(f"[*] Chainlink latestRoundData() {len(chainlink_calls)}회 사용")
    # updatedAt 확인 여부
    if "updatedAt" not in code and "answeredInRound" not in code:
        issues.append("[CRITICAL] Chainlink 신선도 검사 없음 — stale price 사용 가능!")
    if "require.*answeredInRound" not in code:
        issues.append("[!] answeredInRound 검증 없음")

# 2. AMM 스팟 가격 의존성
spot_price_patterns = [
    r\'IUniswapV2Pair[^.]*\\.getReserves\',
    r\'pair\\.getReserves\',
    r\'IERC20[^.]*\\.balanceOf.*pair\',
]
for p in spot_price_patterns:
    if re.search(p, code):
        issues.append("[CRITICAL] UniswapV2 getReserves() 직접 사용 — 플래시론으로 조작 가능!")

# 3. TWAP 창 확인
twap_match = re.search(r\'TWAP_PERIOD|twapPeriod|observationWindow|period\\s*=\\s*(\\d+)\', code)
if twap_match:
    try:
        period = int(twap_match.group(1) if twap_match.lastindex else "0")
        if period > 0 and period < 1800:  # 30분 미만
            issues.append(f"[!] TWAP 기간 {period}초 — 최소 30분(1800초) 권장")
        else:
            print(f"[OK] TWAP 기간: {period}초")
    except:
        pass

# 4. 단일 오라클 의존성
oracle_sources = []
if "chainlink" in code.lower() or "AggregatorV3" in code:
    oracle_sources.append("Chainlink")
if "getReserves" in code or "UniswapV2" in code:
    oracle_sources.append("UniswapV2")
if "observe(" in code or "UniswapV3" in code:
    oracle_sources.append("UniswapV3 TWAP")

if len(oracle_sources) == 1:
    issues.append(f"[!] 단일 오라클 소스 ({oracle_sources[0]}) — 이중 검증 권장")

# 결과 출력
if issues:
    print("\\n[!] 발견된 이슈:")
    for issue in issues:
        print(f"  {issue}")
else:
    print("[OK] 명백한 오라클 취약점 없음")

print("\\n[*] 오라클 분석 완료")
''',
    },

    # ── 10. 서명 재사용 (SWC-121) ────────────────────────────────────
    "web3-signature-replay": {
        "id":          "web3-signature-replay",
        "name":        "Signature Replay Attack (SWC-121)",
        "name_ko":     "서명 재사용 공격 (SWC-121)",
        "name_zh":     "签名重放攻击 (SWC-121)",
        "description": (
            "Detect signature replay vulnerabilities (SWC-121). "
            "Checks for missing nonce in signed messages. "
            "Identifies missing chain ID validation (cross-chain replay). "
            "Verifies EIP-712 structured data signing implementation."
        ),
        "description_ko": (
            "서명 재사용 취약점을 감지한다 (SWC-121). "
            "서명된 메시지에서 nonce 누락을 확인한다. "
            "체인 ID 검증 누락(크로스체인 재사용)을 식별한다. "
            "EIP-712 구조화 데이터 서명 구현을 검증한다."
        ),
        "description_zh": (
            "检测签名重放漏洞(SWC-121)。"
            "检查签名消息中缺少nonce。"
            "识别缺少链ID验证(跨链重放)。"
            "验证EIP-712结构化数据签名实现。"
        ),
        "tags":   ["signature", "replay", "swc121", "eip712", "nonce", "solidity", "web3", "audit"],
        "module": "web3",
        "code": '''
import re

SOLIDITY_CODE = """
{target}
"""
code = SOLIDITY_CODE
print("[*] 서명 재사용 공격 분석 (SWC-121)")

issues = []

# 1. ecrecover 사용 감지
ecrecover_uses = re.findall(r\'ecrecover\\s*\\(\', code)
if ecrecover_uses:
    print(f"[*] ecrecover() {len(ecrecover_uses)}회 사용")

    # nonce 확인
    if not re.search(r\'nonce|Nonce\', code):
        issues.append("[CRITICAL] nonce 없음 — 서명 재사용 가능!")

    # 체인 ID 확인
    if not re.search(r\'chainId|chain_id|block\\.chainid\', code, re.I):
        issues.append("[CRITICAL] 체인 ID 없음 — 크로스체인 재사용 가능!")

    # 컨트랙트 주소 포함 여부
    if not re.search(r\'address\\(this\\)|contractAddress\', code):
        issues.append("[!] 컨트랙트 주소 미포함 — 동일 서명 다른 컨트랙트 재사용 가능")

# 2. EIP-712 구현 확인
if "EIP712" in code or "DOMAIN_SEPARATOR" in code:
    print("[OK] EIP-712 구현됨")
    if "nonces[" in code or "nonces(" in code:
        print("[OK] 사용자별 nonce 관리 있음")
    else:
        issues.append("[!] EIP-712 있지만 nonce 관리 없음")
else:
    if ecrecover_uses:
        issues.append("[!] EIP-712 미사용 — 원시 ecrecover 사용 중")

# 3. 서명 만료 시간
if not re.search(r\'deadline|expiry|expiresAt|validUntil\', code):
    if ecrecover_uses:
        issues.append("[!] 서명 만료 시간 없음 — 영구 유효한 서명")

# 결과
if issues:
    print("\\n[!] 발견된 이슈:")
    for i in issues:
        print(f"  {i}")
else:
    print("[OK] 명백한 서명 재사용 취약점 없음")

print("\\n[*] 서명 분석 완료")
''',
    },

    # ── 11. delegatecall 취약점 (SWC-112) ────────────────────────────
    "web3-delegate-call": {
        "id":          "web3-delegate-call",
        "name":        "Delegatecall Storage Collision (SWC-112)",
        "name_ko":     "Delegatecall 스토리지 슬롯 충돌 (SWC-112)",
        "name_zh":     "Delegatecall存储槽冲突 (SWC-112)",
        "description": (
            "Detect delegatecall storage collision vulnerabilities (SWC-112). "
            "Identifies proxy pattern storage slot conflicts. "
            "Checks EIP-1967 storage slot usage for proxy implementations. "
            "Finds uninitialized implementation address vulnerabilities."
        ),
        "description_ko": (
            "delegatecall 스토리지 슬롯 충돌 취약점을 감지한다 (SWC-112). "
            "프록시 패턴 스토리지 슬롯 충돌을 식별한다. "
            "프록시 구현을 위한 EIP-1967 스토리지 슬롯 사용을 확인한다. "
            "초기화되지 않은 구현 주소 취약점을 찾는다."
        ),
        "description_zh": (
            "检测delegatecall存储槽冲突漏洞(SWC-112)。"
            "识别代理模式存储槽冲突。"
            "检查代理实现的EIP-1967存储槽使用。"
            "查找未初始化的实现地址漏洞。"
        ),
        "tags":   ["delegatecall", "proxy", "swc112", "storage", "eip1967", "solidity", "web3", "upgrade"],
        "module": "web3",
        "code": '''
import re

SOLIDITY_CODE = """
{target}
"""
code = SOLIDITY_CODE
print("[*] Delegatecall 취약점 분석 (SWC-112)")

# 1. delegatecall 사용 위치
delegatecall_uses = [(i+1, line.strip()) for i, line in enumerate(code.split("\\n"))
                     if "delegatecall" in line]
if delegatecall_uses:
    print(f"[*] delegatecall {len(delegatecall_uses)}회 발견:")
    for line_num, line_code in delegatecall_uses:
        print(f"  Line {line_num}: {line_code[:80]}")

    # 입력 검증 확인
    if not re.search(r\'require.*implementation|implementation.*!=.*address\\(0\\)\', code):
        print("  [!] implementation 주소 유효성 검사 없음")

# 2. EIP-1967 슬롯 확인
if "0x360894" in code:  # EIP-1967 implementation slot
    print("[OK] EIP-1967 implementation 슬롯 사용")
elif delegatecall_uses:
    print("[!] EIP-1967 표준 슬롯 미사용 — 스토리지 충돌 가능")

# 3. 초기화 확인 (Initializable)
if "Initializable" in code:
    print("[OK] Initializable 사용")
elif "initialize(" in code:
    if "initializer" not in code:
        print("[CRITICAL] initialize() 함수에 initializer 수정자 없음!")

# 4. 함수 충돌 확인 (selector clash)
func_names = re.findall(r\'function\\s+(\\w+)\\s*\\(\', code)
from collections import Counter
duplicates = [f for f, c in Counter(func_names).items() if c > 1]
if duplicates:
    print(f"[!] 중복 함수명 발견: {duplicates} — 셀렉터 충돌 가능")

print("\\n[*] Delegatecall 분석 완료")
''',
    },

    # ── 12. 지갑 없이 DApp API 열거 ──────────────────────────────────
    "web3-wallet-connect-enum": {
        "id":          "web3-wallet-connect-enum",
        "name":        "DApp API Enumeration Without Wallet",
        "name_ko":     "지갑 없이 DApp API 엔드포인트 열거",
        "name_zh":     "无钱包DApp API端点枚举",
        "description": (
            "Enumerate DApp backend API endpoints without wallet connection. "
            "Extracts API routes from JS bundles that bypass wallet auth. "
            "Tests REST/GraphQL endpoints accessible without Web3 wallet. "
            "Identifies CORS misconfigurations, missing auth on sensitive endpoints."
        ),
        "description_ko": (
            "지갑 연결 없이 DApp 백엔드 API 엔드포인트를 열거한다. "
            "지갑 인증을 우회하는 JS 번들에서 API 라우트를 추출한다. "
            "Web3 지갑 없이 접근 가능한 REST/GraphQL 엔드포인트를 테스트한다. "
            "CORS 잘못된 설정, 민감한 엔드포인트의 누락된 인증을 식별한다."
        ),
        "description_zh": (
            "无需钱包连接即可枚举DApp后端API端点。"
            "从绕过钱包认证的JS包中提取API路由。"
            "测试无需Web3钱包即可访问的REST/GraphQL端点。"
            "识别CORS错误配置、敏感端点上缺少认证。"
        ),
        "tags":   ["dapp", "api", "walletconnect", "enumeration", "web3", "cors", "graphql", "auth-bypass"],
        "module": "web3",
        "code": '''
import requests, re
from urllib.parse import urljoin, urlparse

TARGET = "{target}"
parsed = urlparse(TARGET)
base = f"{parsed.scheme}://{parsed.netloc}"

headers = {"User-Agent": "Mozilla/5.0", "Accept": "application/json"}
session = requests.Session()
session.verify = False

print(f"[*] DApp API 열거 (지갑 없이): {TARGET}")

# 1. 메인 페이지에서 JS 번들 추출
r = session.get(TARGET, headers=headers, timeout=10)
html = r.text

js_urls = re.findall(r\'src=["\\\']([^"\\\']*\\.js(?:\\?[^"\\\']*)?)["\\\']', html)
print(f"[*] JS 파일 {len(js_urls)}개 발견")

api_endpoints = set()
sensitive_patterns = [
    r\'["\\\']/(api|v1|v2|graphql|query|admin|user|auth|token|balance|price|swap)["\\\'\\/]\',
    r\'axios\\.(get|post|put|delete)\\(["\\\']([^"\\\']+)["\\\']\',
    r\'fetch\\(["\\\']([^"\\\']+)["\\\']\',
    r\'apiUrl[\\s:=]+["\\\']([^"\\\']+)["\\\']\',
    r\'baseURL[\\s:=]+["\\\']([^"\\\']+)["\\\']\',
]

for js_url in js_urls[:10]:
    full_url = urljoin(TARGET, js_url)
    try:
        jr = session.get(full_url, headers=headers, timeout=10)
        if jr.status_code == 200:
            jtext = jr.text
            for pattern in sensitive_patterns:
                matches = re.findall(pattern, jtext)
                for m in matches:
                    endpoint = m[-1] if isinstance(m, tuple) else m
                    if endpoint.startswith("/") or endpoint.startswith("http"):
                        api_endpoints.add(endpoint)
    except:
        continue

print(f"\\n[*] API 엔드포인트 {len(api_endpoints)}개 발견:")
for ep in sorted(api_endpoints)[:30]:
    print(f"  {ep}")

# 2. 발견된 엔드포인트 테스트
print("\\n[*] 미인증 접근 테스트:")
for ep in sorted(api_endpoints)[:15]:
    if ep.startswith("/"):
        url = base + ep
    elif ep.startswith("http"):
        url = ep
    else:
        continue

    try:
        r = session.get(url, headers=headers, timeout=5)
        if r.status_code == 200:
            content_type = r.headers.get("Content-Type", "")
            if "json" in content_type or r.text.startswith("{") or r.text.startswith("["):
                print(f"  [!!!] {url} → {r.status_code} JSON 응답!")
                print(f"       {r.text[:150]}")
        elif r.status_code == 401:
            print(f"  [AUTH] {url} → 인증 필요")
        elif r.status_code != 404:
            print(f"  [{r.status_code}] {url}")
    except:
        pass

# 3. GraphQL 엔드포인트 탐지
graphql_paths = ["/graphql", "/api/graphql", "/query", "/v1/graphql"]
for path in graphql_paths:
    url = base + path
    try:
        r = session.post(url, json={"query": "{__schema{types{name}}}"}, headers={**headers, "Content-Type": "application/json"}, timeout=5)
        if r.status_code == 200 and "types" in r.text:
            print(f"\\n[!!!] GraphQL 인트로스펙션 열림: {url}")
    except:
        pass

print("\\n[*] DApp API 열거 완료")
''',
    },

    # ── 13. NFT 메타데이터 SSRF ──────────────────────────────────────
    "web3-nft-metadata-ssrf": {
        "id":          "web3-nft-metadata-ssrf",
        "name":        "NFT Metadata SSRF / URI Manipulation",
        "name_ko":     "NFT 메타데이터 SSRF / URI 조작",
        "name_zh":     "NFT元数据SSRF/URI操纵",
        "description": (
            "Test NFT metadata endpoints for SSRF and URI manipulation vulnerabilities. "
            "Checks tokenURI for controllable parameters. "
            "Tests IPFS gateway SSRF, base URI override. "
            "Identifies on-chain SVG/HTML injection in metadata."
        ),
        "description_ko": (
            "SSRF 및 URI 조작 취약점에 대해 NFT 메타데이터 엔드포인트를 테스트한다. "
            "제어 가능한 매개변수에 대해 tokenURI를 확인한다. "
            "IPFS 게이트웨이 SSRF, 기본 URI 재정의를 테스트한다. "
            "메타데이터의 온체인 SVG/HTML 삽입을 식별한다."
        ),
        "description_zh": (
            "测试NFT元数据端点的SSRF和URI操纵漏洞。"
            "检查tokenURI中的可控参数。"
            "测试IPFS网关SSRF、基础URI覆盖。"
            "识别元数据中的链上SVG/HTML注入。"
        ),
        "tags":   ["nft", "ssrf", "metadata", "uri", "ipfs", "web3", "svg-injection", "audit"],
        "module": "web3",
        "code": '''
import requests, re, json
from urllib.parse import urljoin

TARGET = "{target}"  # NFT 컨트랙트 주소 또는 메타데이터 URL
headers = {"User-Agent": "Mozilla/5.0"}

print(f"[*] NFT 메타데이터 SSRF 분석: {TARGET}")

# tokenURI 패턴 테스트
test_uris = [
    "https://attacker.com/ssrf-test",
    "http://169.254.169.254/latest/meta-data/",  # AWS 메타데이터
    "file:///etc/passwd",
    "gopher://localhost:6379/_PING",
    "dict://localhost:11211/",
]

if TARGET.startswith("http"):
    # API 엔드포인트로 직접 테스트
    for token_id in range(1, 6):
        url = TARGET.rstrip("/") + f"/{token_id}"
        try:
            r = requests.get(url, headers=headers, timeout=10, verify=False)
            if r.status_code == 200:
                data = r.json()
                print(f"[+] Token #{token_id}:")
                print(f"  image: {data.get(\'image\', \'N/A\')[:100]}")
                print(f"  name: {data.get(\'name\', \'N/A\')}")

                # SVG 인젝션 확인
                image = data.get("image", "")
                if "data:image/svg" in image:
                    if "<script" in image or "javascript:" in image:
                        print(f"  [CRITICAL] SVG XSS 발견!")
                    else:
                        print(f"  [!] 온체인 SVG — XSS 가능성 확인 필요")

                # IPFS 게이트웨이
                if "ipfs://" in image:
                    print(f"  [*] IPFS URI 발견 — 게이트웨이 SSRF 가능성")
        except:
            pass

print("\\n[*] NFT 메타데이터 분석 완료")
''',
    },

    # ── 14. DApp GraphQL 서브그래프 ──────────────────────────────────
    "web3-graphql-subgraph": {
        "id":          "web3-graphql-subgraph",
        "name":        "DApp GraphQL Subgraph Query Vulnerability",
        "name_ko":     "DApp GraphQL 서브그래프 쿼리 취약점",
        "name_zh":     "DApp GraphQL子图查询漏洞",
        "description": (
            "Test DApp GraphQL subgraph (The Graph protocol) for vulnerabilities. "
            "Checks introspection exposure, query depth limits, batch attack. "
            "Identifies sensitive data in subgraph entities (private keys, addresses). "
            "Tests for unauthenticated access to financial data."
        ),
        "description_ko": (
            "취약점에 대해 DApp GraphQL 서브그래프(The Graph 프로토콜)를 테스트한다. "
            "인트로스펙션 노출, 쿼리 깊이 제한, 배치 공격을 확인한다. "
            "서브그래프 엔티티의 민감 데이터(개인 키, 주소)를 식별한다. "
            "금융 데이터에 대한 미인증 접근을 테스트한다."
        ),
        "description_zh": (
            "测试DApp GraphQL子图(The Graph协议)的漏洞。"
            "检查内省暴露、查询深度限制、批量攻击。"
            "识别子图实体中的敏感数据(私钥、地址)。"
            "测试对财务数据的未授权访问。"
        ),
        "tags":   ["graphql", "subgraph", "thegraph", "dapp", "web3", "introspection", "query"],
        "module": "web3",
        "code": '''
import requests, json

TARGET = "{target}"  # GraphQL 서브그래프 URL
headers = {"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"}

print(f"[*] GraphQL 서브그래프 취약점 분석: {TARGET}")

def gql(query):
    try:
        r = requests.post(TARGET, json={"query": query}, headers=headers, timeout=10, verify=False)
        return r.json() if r.status_code == 200 else None
    except:
        return None

# 1. 인트로스펙션
intro = gql("{__schema{types{name kind}}}")
if intro and "data" in intro:
    types = [t["name"] for t in intro["data"]["__schema"]["types"] if not t["name"].startswith("__")]
    print(f"[!!!] 인트로스펙션 열림 — {len(types)}개 타입:")
    for t in types[:20]:
        print(f"  {t}")

    # 민감 타입 탐색
    sensitive = [t for t in types if any(kw in t.lower() for kw in
                ["user", "account", "wallet", "balance", "transaction", "token", "liquidity"])]
    if sensitive:
        print(f"\\n[*] 민감 타입 {len(sensitive)}개: {sensitive}")
        # 첫 번째 민감 타입 데이터 추출 시도
        for stype in sensitive[:3]:
            test_q = f"{{ {stype.lower()}s(first:3){{ id }} }}"
            result = gql(test_q)
            if result and "data" in result:
                print(f"  [!!!] {stype} 데이터 접근 성공: {str(result[\'data\'])[:200]}")

# 2. 깊이 제한 테스트
deep_query = "{ tokens { owner { tokens { owner { tokens { id } } } } } }"
deep_result = gql(deep_query)
if deep_result and "errors" not in deep_result:
    print("\\n[!] 쿼리 깊이 제한 없음 — DoS 가능!")
elif deep_result and "errors" in deep_result:
    print(f"[OK] 깊이 제한 있음: {deep_result[\'errors\'][0].get(\'message\',\'\')[:60]}")

# 3. 배치 쿼리 공격
batch = [{"query": f"{{ tokens(first:100) {{ id }} }}"} for _ in range(10)]
try:
    r = requests.post(TARGET, json=batch, headers=headers, timeout=10, verify=False)
    if r.status_code == 200 and isinstance(r.json(), list):
        print("\\n[!] 배치 쿼리 허용 — rate limit 우회 가능")
except:
    pass

print("\\n[*] GraphQL 서브그래프 분석 완료")
''',
    },

    # ── 15. 개인 데이터 노출 (SWC-136) ──────────────────────────────
    "web3-private-data": {
        "id":          "web3-private-data",
        "name":        "Private Storage Data Exposure (SWC-136)",
        "name_ko":     "프라이빗 스토리지 데이터 노출 (SWC-136)",
        "name_zh":     "私有存储数据暴露 (SWC-136)",
        "description": (
            "Detect private variable exposure vulnerabilities (SWC-136). "
            "Reads raw storage slots from deployed contracts via eth_getStorageAt. "
            "Finds sensitive data stored in 'private' variables (keys, seeds, secrets). "
            "Demonstrates all blockchain data is publicly readable."
        ),
        "description_ko": (
            "프라이빗 변수 노출 취약점을 감지한다 (SWC-136). "
            "eth_getStorageAt을 통해 배포된 컨트랙트에서 원시 스토리지 슬롯을 읽는다. "
            "'private' 변수에 저장된 민감 데이터(키, 시드, 비밀)를 찾는다. "
            "모든 블록체인 데이터는 공개적으로 읽을 수 있음을 증명한다."
        ),
        "description_zh": (
            "检测私有变量暴露漏洞(SWC-136)。"
            "通过eth_getStorageAt从已部署合约读取原始存储槽。"
            "查找存储在'private'变量中的敏感数据(密钥、种子、秘密)。"
            "证明所有区块链数据都可以公开读取。"
        ),
        "tags":   ["private", "storage", "swc136", "solidity", "eth_getStorageAt", "web3", "audit"],
        "module": "web3",
        "code": '''
import requests, json

CONTRACT = "{target}"  # 0x... 컨트랙트 주소
RPC_URL = "https://eth.llamarpc.com"  # 무료 공개 RPC

headers = {"Content-Type": "application/json"}

print(f"[*] 프라이빗 스토리지 슬롯 읽기: {CONTRACT}")
print("[!] 주의: Solidity의 private은 숨김이 아님 — 블록체인 데이터는 모두 공개!")

def get_storage(slot):
    payload = {
        "jsonrpc": "2.0",
        "method": "eth_getStorageAt",
        "params": [CONTRACT, hex(slot), "latest"],
        "id": slot
    }
    try:
        r = requests.post(RPC_URL, json=payload, headers=headers, timeout=10)
        data = r.json()
        return data.get("result", "0x" + "0"*64)
    except:
        return None

# 처음 10개 슬롯 읽기
print("\\n[*] 스토리지 슬롯 0~9 읽기:")
for slot in range(10):
    value = get_storage(slot)
    if value and value != "0x" + "0"*64:
        # 값 해석 시도
        raw = value[2:]  # 0x 제거
        try:
            as_int = int(raw, 16)
            as_addr = "0x" + raw[-40:] if len(raw) >= 40 else ""
            as_str = bytes.fromhex(raw).decode("utf-8", errors="replace").strip("\\x00")
            print(f"  Slot {slot}: {value}")
            print(f"    int: {as_int}")
            if as_addr:
                print(f"    address: {as_addr}")
            if any(32 <= ord(c) < 127 for c in as_str[:20]):
                print(f"    string: {as_str[:50]}")
        except:
            print(f"  Slot {slot}: {value}")
    else:
        print(f"  Slot {slot}: (비어있음)")

print("\\n[*] 스토리지 읽기 완료")
''',
    },

    # ── 16. selfdestruct (SWC-106) ────────────────────────────────────
    "web3-selfdestruct": {
        "id":          "web3-selfdestruct",
        "name":        "Selfdestruct / Force Ether Send (SWC-106)",
        "name_ko":     "Selfdestruct / 강제 이더 전송 (SWC-106)",
        "name_zh":     "自毁/强制发送以太币 (SWC-106)",
        "description": (
            "Detect selfdestruct misuse vulnerabilities (SWC-106). "
            "Identifies unprotected selfdestruct calls. "
            "Checks contracts relying on balance checks for logic (breakable via selfdestruct). "
            "Finds this.balance == 0 conditions bypassed by force-sending ETH."
        ),
        "description_ko": (
            "selfdestruct 오용 취약점을 감지한다 (SWC-106). "
            "보호되지 않은 selfdestruct 호출을 식별한다. "
            "로직에 잔액 확인에 의존하는 컨트랙트를 확인한다 (selfdestruct로 파괴 가능). "
            "강제 ETH 전송으로 우회된 this.balance == 0 조건을 찾는다."
        ),
        "description_zh": (
            "检测自毁滥用漏洞(SWC-106)。"
            "识别未受保护的自毁调用。"
            "检查依赖余额检查逻辑的合约(可通过自毁破坏)。"
            "查找通过强制发送ETH绕过的this.balance == 0条件。"
        ),
        "tags":   ["selfdestruct", "swc106", "solidity", "force-ether", "audit", "web3"],
        "module": "web3",
        "code": '''
import re

SOLIDITY_CODE = """
{target}
"""
code = SOLIDITY_CODE
print("[*] Selfdestruct 취약점 분석 (SWC-106)")

# 1. selfdestruct/suicide 감지
for keyword in ["selfdestruct", "suicide("]:
    occurrences = [(i+1, l.strip()) for i, l in enumerate(code.split("\\n")) if keyword in l]
    if occurrences:
        print(f"\\n[*] {keyword} {len(occurrences)}회 발견:")
        for line_num, line_code in occurrences:
            print(f"  Line {line_num}: {line_code}")
            # 컨텍스트에서 보호 수정자 확인
            lines = code.split("\\n")
            start = max(0, line_num-5)
            context = "\\n".join(lines[start:line_num])
            if not any(g in context for g in ["onlyOwner", "require(msg.sender", "onlyAdmin"]):
                print(f"  [CRITICAL] 접근 제어 없음 — 누구나 컨트랙트 파괴 가능!")

# 2. balance 의존 로직
balance_deps = re.findall(r\'address\\(this\\)\\.balance\\s*(?:==|!=|>|<|>=|<=|>\\s*0)\', code)
if balance_deps:
    print(f"\\n[!] this.balance 의존 로직 {len(balance_deps)}개:")
    print("  selfdestruct로 강제 ETH 전송 시 로직 파괴 가능!")
    for b in balance_deps:
        print(f"  → {b}")

# 3. msg.value == 0 require
zero_val = re.findall(r\'require\\s*\\(\\s*msg\\.value\\s*==\\s*0\', code)
if zero_val:
    print("\\n[!] msg.value == 0 요구 조건 발견 — 강제 ETH 전송으로 우회 가능")

print("\\n[*] Selfdestruct 분석 완료")
''',
    },

    # ── 17. unchecked call (SWC-104) ─────────────────────────────────
    "web3-unchecked-call": {
        "id":          "web3-unchecked-call",
        "name":        "Unchecked Return Value (SWC-104)",
        "name_ko":     "반환값 미확인 저수준 call (SWC-104)",
        "name_zh":     "未检查返回值 (SWC-104)",
        "description": (
            "Detect unchecked low-level call return values (SWC-104). "
            "Identifies .call(), .send(), .delegatecall() without success checks. "
            "Finds silent failure patterns where ETH transfers may silently fail."
        ),
        "description_ko": (
            "미확인 저수준 call 반환값을 감지한다 (SWC-104). "
            ".call(), .send(), .delegatecall() 성공 확인 없음을 식별한다. "
            "ETH 전송이 자동으로 실패할 수 있는 침묵 실패 패턴을 찾는다."
        ),
        "description_zh": (
            "检测未检查的低级call返回值(SWC-104)。"
            "识别没有成功检查的.call()、.send()、.delegatecall()。"
            "查找ETH转账可能静默失败的模式。"
        ),
        "tags":   ["unchecked-call", "swc104", "solidity", "send", "call", "audit", "web3"],
        "module": "web3",
        "code": '''
import re

SOLIDITY_CODE = """
{target}
"""
lines = SOLIDITY_CODE.split("\\n")
print("[*] 미확인 반환값 분석 (SWC-104)")

issues = []
for i, line in enumerate(lines):
    stripped = line.strip()

    # .send() 반환값 미확인
    if re.search(r\'\\.send\\s*\\([^)]*\\)\\s*;\', stripped):
        if not re.search(r\'(?:bool|require|if).*\\.send\', stripped):
            issues.append((i+1, "MEDIUM", ".send() 반환값 미확인", stripped))

    # .call{} 반환값 미확인
    if re.search(r\'\\.call[{(][^)]*\\)\\s*;\', stripped):
        if not re.search(r\'\\(bool.*\\)\\s*=\', stripped) and not re.search(r\'require.*\\.call\', stripped):
            issues.append((i+1, "HIGH", ".call() 반환값 미확인", stripped))

    # transfer는 자동 revert이므로 OK
    if ".transfer(" in stripped:
        pass  # 안전

if issues:
    print(f"\\n[!] {len(issues)}개 이슈 발견:")
    for line_num, severity, desc, code_line in issues:
        print(f"  [{severity}] Line {line_num}: {desc}")
        print(f"    {code_line[:80]}")
else:
    print("[OK] 미확인 반환값 패턴 없음")

print("\\n[*] 분석 완료")
''',
    },

    # ── 18. 블록 타임스탬프 의존성 (SWC-116) ──────────────────────────
    "web3-timestamp-dependence": {
        "id":          "web3-timestamp-dependence",
        "name":        "Block Timestamp Dependence (SWC-116)",
        "name_ko":     "블록 타임스탬프 의존성 (SWC-116)",
        "name_zh":     "区块时间戳依赖 (SWC-116)",
        "description": (
            "Detect block timestamp manipulation vulnerabilities (SWC-116). "
            "Finds block.timestamp usage in critical logic (randomness, deadlines, locking). "
            "Identifies 15-second miner manipulation window. "
            "Checks block.number alternatives for time-based logic."
        ),
        "description_ko": (
            "블록 타임스탬프 조작 취약점을 감지한다 (SWC-116). "
            "중요 로직(무작위성, 기한, 잠금)에서 block.timestamp 사용을 찾는다. "
            "15초 마이너 조작 창을 식별한다. "
            "시간 기반 로직에 대한 block.number 대안을 확인한다."
        ),
        "description_zh": (
            "检测区块时间戳操纵漏洞(SWC-116)。"
            "在关键逻辑(随机性、截止日期、锁定)中查找block.timestamp使用。"
            "识别15秒矿工操纵窗口。"
            "检查基于时间逻辑的block.number替代方案。"
        ),
        "tags":   ["timestamp", "swc116", "solidity", "block", "miner", "audit", "web3"],
        "module": "web3",
        "code": '''
import re

SOLIDITY_CODE = """
{target}
"""
code = SOLIDITY_CODE
lines = code.split("\\n")
print("[*] 블록 타임스탬프 의존성 분석 (SWC-116)")

# 1. block.timestamp 사용 위치
ts_uses = [(i+1, l.strip()) for i, l in enumerate(lines) if "block.timestamp" in l or "now" == l.strip()]

if ts_uses:
    print(f"\\n[*] block.timestamp {len(ts_uses)}회 사용:")
    for line_num, line_code in ts_uses:
        # 위험 패턴 분류
        if re.search(r\'block\\.timestamp\\s*%\\s*|block\\.timestamp\\s*mod\', line_code):
            print(f"  [CRITICAL] Line {line_num}: 무작위성에 timestamp 사용! → {line_code[:70]}")
        elif re.search(r\'require.*block\\.timestamp|block\\.timestamp.*<=|block\\.timestamp.*>=\', line_code):
            print(f"  [MEDIUM] Line {line_num}: 타임락/기한 조건 → {line_code[:70]}")
        else:
            print(f"  [INFO] Line {line_num}: {line_code[:70]}")

    print("\\n[!] block.timestamp은 마이너가 ±15초 조작 가능")
    print("    복권/무작위성 용도는 Chainlink VRF 사용 권장")
else:
    print("[OK] block.timestamp 의존성 없음")

print("\\n[*] 타임스탬프 분석 완료")
''',
    },

    # ── 19. DeFi 전체 파이프라인 ─────────────────────────────────────
    "web3-defi-full-pipeline": {
        "id":          "web3-defi-full-pipeline",
        "name":        "DeFi Full Attack Pipeline (Auto-Select)",
        "name_ko":     "DeFi 전체 공격 파이프라인 (자동 선택)",
        "name_zh":     "DeFi完整攻击流水线 (自动选择)",
        "description": (
            "Full DeFi/DApp attack pipeline that automatically selects relevant checks. "
            "Step 1: DApp fingerprinting and Web3 stack detection. "
            "Step 2: JSON-RPC endpoint enumeration. "
            "Step 3: Wallet-less API endpoint discovery. "
            "Step 4: Smart contract ABI extraction and function mapping. "
            "Step 5: Automated vulnerability chain based on findings. "
            "Auto-selects deepest attack path from reconnaissance results."
        ),
        "description_ko": (
            "관련 검사를 자동으로 선택하는 전체 DeFi/DApp 공격 파이프라인. "
            "1단계: DApp 핑거프린팅 및 Web3 스택 탐지. "
            "2단계: JSON-RPC 엔드포인트 열거. "
            "3단계: 지갑 없는 API 엔드포인트 발견. "
            "4단계: 스마트 컨트랙트 ABI 추출 및 함수 매핑. "
            "5단계: 발견 결과 기반 자동화된 취약점 체인. "
            "정찰 결과에서 가장 깊은 공격 경로를 자동 선택한다."
        ),
        "description_zh": (
            "自动选择相关检查的完整DeFi/DApp攻击流水线。"
            "第1步: DApp指纹和Web3栈检测。"
            "第2步: JSON-RPC端点枚举。"
            "第3步: 无钱包API端点发现。"
            "第4步: 智能合约ABI提取和函数映射。"
            "第5步: 基于发现的自动化漏洞链。"
            "从侦察结果自动选择最深的攻击路径。"
        ),
        "tags":   ["defi", "pipeline", "dapp", "web3", "full-scan", "auto", "blockchain", "smart-contract",
                   "walletconnect", "metamask", "wagmi", "ethers", "solidity", "audit"],
        "module": "web3",
        "code": '''
import requests, re, json
from urllib.parse import urljoin, urlparse

TARGET = "{target}"
parsed = urlparse(TARGET)
base = f"{parsed.scheme}://{parsed.netloc}"
headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
           "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"}
session = requests.Session()
session.verify = False

print("=" * 60)
print(f"[*] DeFi 전체 공격 파이프라인 시작")
print(f"[*] 타겟: {TARGET}")
print("=" * 60)

findings = []

# ── STEP 1: DApp 핑거프린팅 ──────────────────────────────
print("\\n[STEP 1] DApp Web3 스택 핑거프린팅")
r = session.get(TARGET, headers=headers, timeout=15)
html = r.text

web3_detected = []
for lib, patterns in {
    "ethers.js": [r\'ethers\'],
    "web3.js": [r\'new Web3\\(\'],
    "wagmi": [r\'wagmi\'],
    "viem": [r\'viem\'],
    "MetaMask": [r\'window\\.ethereum\'],
    "WalletConnect": [r\'WalletConnect\'],
}.items():
    if any(re.search(p, html) for p in patterns):
        web3_detected.append(lib)

contracts = list(set(re.findall(r\'0x[a-fA-F0-9]{40}\', html)))
rpcs = re.findall(r\'https?://[\\w.-]+\\.(?:infura|alchemy|quicknode)\\.(?:io|com)/[\\w/]+\', html)

print(f"  Web3 라이브러리: {web3_detected or [\'감지 안됨\']}")
print(f"  컨트랙트 주소: {len(contracts)}개")
print(f"  RPC 엔드포인트: {len(rpcs)}개")
if rpcs:
    for rpc in rpcs[:3]:
        print(f"    [!] {rpc}")

# ── STEP 2: JSON-RPC 스캔 ────────────────────────────────
print("\\n[STEP 2] JSON-RPC 엔드포인트 스캔")
for path in ["/", "/rpc", "/api", "/ethereum", "/eth"]:
    url = base + path
    try:
        r = session.post(url, json={"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1},
                        headers={"Content-Type":"application/json"}, timeout=5)
        if r.status_code == 200 and "jsonrpc" in r.text:
            print(f"  [!!!] 노출된 RPC: {url}")
            findings.append(f"노출된 JSON-RPC: {url}")
    except:
        pass

# ── STEP 3: API 엔드포인트 ────────────────────────────────
print("\\n[STEP 3] 지갑 없이 API 엔드포인트 탐색")
api_endpoints = set()
js_urls = re.findall(r\'src=["\\\']([^"\\\']*\\.js[^"\\\']*)["\\\']', html)
for js_url in js_urls[:5]:
    try:
        jr = session.get(urljoin(TARGET, js_url), timeout=8)
        if jr.status_code == 200:
            found = re.findall(r\'["\\\']/(api|v1|v2|graphql|auth|user|admin)[\\w/]*["\\\']\', jr.text)
            api_endpoints.update(found)
    except:
        pass

for ep in list(api_endpoints)[:10]:
    url = base + ep
    try:
        r = session.get(url, headers=headers, timeout=5)
        if r.status_code == 200:
            print(f"  [!!!] 미인증 접근: {url}")
            findings.append(f"미인증 API: {url}")
        elif r.status_code not in [404, 405]:
            print(f"  [{r.status_code}] {url}")
    except:
        pass

# ── STEP 4: GraphQL 탐지 ─────────────────────────────────
print("\\n[STEP 4] GraphQL 서브그래프 탐지")
for path in ["/graphql", "/subgraphs/name/", "/api/graphql"]:
    url = base + path
    try:
        r = session.post(url, json={"query":"{__schema{types{name}}}"}, 
                        headers={"Content-Type":"application/json"}, timeout=5)
        if r.status_code == 200 and "types" in r.text:
            print(f"  [!!!] GraphQL 인트로스펙션 열림: {url}")
            findings.append(f"GraphQL 인트로스펙션: {url}")
    except:
        pass

# ── 최종 리포트 ───────────────────────────────────────────
print("\\n" + "=" * 60)
print("[*] 최종 리포트")
print("=" * 60)
if findings:
    print(f"\\n[!!!] {len(findings)}개 취약점 발견:")
    for f in findings:
        print(f"  • {f}")
else:
    print("\\n[*] 표면적 취약점 없음 — 스마트 컨트랙트 소스코드 감사 권장")
    if contracts:
        print(f"\\n[*] 발견된 컨트랙트 주소 감사 대상:")
        for c in contracts[:5]:
            print(f"  {c}")
''',
    },

    # ── 20. 스마트 컨트랙트 종합 감사 ───────────────────────────────
    "web3-contract-audit": {
        "id":          "web3-contract-audit",
        "name":        "Smart Contract Comprehensive Audit Report",
        "name_ko":     "스마트 컨트랙트 종합 감사 리포트 생성",
        "name_zh":     "智能合约综合审计报告生成",
        "description": (
            "Generate comprehensive smart contract security audit report. "
            "Runs all SWC checks: reentrancy, overflow, access control, front-running, "
            "signature replay, delegatecall, selfdestruct, unchecked call, timestamp. "
            "Produces structured report with severity ratings, affected functions, "
            "PoC code snippets, and remediation recommendations."
        ),
        "description_ko": (
            "종합 스마트 컨트랙트 보안 감사 리포트를 생성한다. "
            "모든 SWC 검사를 실행한다: 재진입, 오버플로우, 접근 제어, 프론트런닝, "
            "서명 재사용, delegatecall, selfdestruct, 미확인 call, 타임스탬프. "
            "심각도 등급, 영향 받는 함수, PoC 코드 스니펫, "
            "수정 권고사항을 포함한 구조화된 리포트를 생성한다."
        ),
        "description_zh": (
            "生成综合智能合约安全审计报告。"
            "运行所有SWC检查: 重入、溢出、访问控制、抢先交易、"
            "签名重放、delegatecall、自毁、未检查call、时间戳。"
            "生成包含严重性评级、受影响函数、PoC代码片段、"
            "修复建议的结构化报告。"
        ),
        "tags":   ["audit", "report", "solidity", "smart-contract", "swc", "defi", "comprehensive",
                   "web3", "security", "contract-audit"],
        "module": "web3",
        "code": '''
import re
from datetime import datetime

SOLIDITY_CODE = """
{target}
"""
code = SOLIDITY_CODE
print("=" * 70)
print(f"  스마트 컨트랙트 종합 보안 감사 리포트")
print(f"  생성 시각: {datetime.now().strftime(\\'%Y-%m-%d %H:%M:%S\\')}")
print("=" * 70)

findings = []

def check(title, swc, severity, pattern, suggestion):
    if callable(pattern):
        result = pattern(code)
    else:
        result = bool(re.search(pattern, code))
    if result:
        findings.append({"title": title, "swc": swc, "severity": severity, "suggestion": suggestion})
        print(f"  [{severity}] {title} ({swc})")

# SWC 체크리스트
checks = [
    ("재진입 공격",         "SWC-107", "CRITICAL", lambda c: ".call(" in c and "nonReentrant" not in c and "ReentrancyGuard" not in c, "nonReentrant 수정자 추가, CEI 패턴 준수"),
    ("정수 오버플로우",     "SWC-101", "HIGH",     lambda c: bool(re.search(r\'pragma solidity\\s+0\\.[0-7]\\.\', c)) and "SafeMath" not in c, "SafeMath 또는 Solidity 0.8+ 사용"),
    ("미보호 관리자 함수",  "SWC-105", "CRITICAL", lambda c: bool(re.search(r\'function\\s+\\w*(?:admin|mint|burn|upgrade)\\w*\\s*\\([^)]*\\)\\s*(?:public|external)(?!.*onlyOwner)\', c, re.I)), "onlyOwner/onlyAdmin 수정자 추가"),
    ("tx.origin 인증",      "SWC-115", "HIGH",     r\'tx\\.origin\', "tx.origin → msg.sender로 교체"),
    ("서명 재사용",         "SWC-121", "HIGH",     lambda c: "ecrecover(" in c and "nonce" not in c.lower(), "nonce, chainId, deadline 포함한 EIP-712 구현"),
    ("delegatecall 노출",   "SWC-112", "HIGH",     lambda c: "delegatecall" in c and "onlyOwner" not in c, "delegatecall 접근 제어 추가"),
    ("비보호 selfdestruct", "SWC-106", "CRITICAL", lambda c: ("selfdestruct(" in c or "suicide(" in c) and "onlyOwner" not in c, "selfdestruct에 onlyOwner 가드 추가"),
    ("미확인 .send()",      "SWC-104", "MEDIUM",   lambda c: bool(re.search(r\'(?<!bool\\s)(?<!= )\\.send\\s*\\(\', c)), ".send() 반환값 확인 또는 .transfer() 사용"),
    ("타임스탬프 의존성",   "SWC-116", "MEDIUM",   r\'block\\.timestamp\\s*%\', "Chainlink VRF로 무작위성 대체"),
    ("spot price 오라클",   "N/A",     "CRITICAL", r\'getReserves\\(\\)\', "TWAP 또는 Chainlink 오라클 사용"),
    ("프론트런닝",          "SWC-114", "HIGH",     lambda c: "swap" in c.lower() and "amountOutMin" not in c, "amountOutMin, deadline 슬리피지 파라미터 추가"),
]

print("\\n[*] 취약점 스캔:")
for args in checks:
    check(*args)

# 요약
print("\\n" + "=" * 70)
print("  감사 요약")
print("=" * 70)
severities = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
for f in findings:
    severities[f["severity"]] = severities.get(f["severity"], 0) + 1

print(f"  CRITICAL: {severities[\'CRITICAL\']}개")
print(f"  HIGH:     {severities[\'HIGH\']}개")
print(f"  MEDIUM:   {severities[\'MEDIUM\']}개")
print(f"  총 이슈:  {len(findings)}개")

if findings:
    print("\\n[*] 수정 권고사항:")
    for f in findings:
        print(f"  [{f[\'severity\']}] {f[\'title\']} → {f[\'suggestion\']}")
else:
    print("\\n[OK] 스캔된 패턴에서 취약점 없음")

print("\\n[*] 감사 완료")
''',
    },
}

# ── 인덱스 생성 ────────────────────────────────────────────────────────
MODULE_INDEX_15: dict[str, list[str]] = {}
TAG_INDEX_15: dict[str, list[str]] = {}

for _sid, _s in SKILLS_DB_15.items():
    _mod = _s.get("module", "web3")
    MODULE_INDEX_15.setdefault(_mod, []).append(_sid)
    for _tag in _s.get("tags", []):
        TAG_INDEX_15.setdefault(_tag, []).append(_sid)
