"""
skills_data15.py — DApp / Web3 / Smart Contract 전용 공격·감사 스킬 DB
bingo v3.2.62

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
  [9] Trail of Bits Blog — EIP-7730 Blind Signing
      https://blog.trailofbits.com/2025/08/27/implement-eip-7730-today/
      (Bybit $1.5B hack: delegatecall op-type 0→1 tampering, blind signing, clear signing)
  [10] Cyfrin — Smart Contract Auditor Roadmap
       https://www.cyfrin.io/blog/how-to-become-a-smart-contract-auditor
       (Weak randomness SWC-120, DoS gas limit, MEV, signature replay patterns)
  [11] HackerNoon — Code Injection Cryptocurrency Theft
       https://hackernoon.com/how-one-hacker-stole-thousands-of-dollars-worth-of-cryptocurrency-with-a-classic-code-injection-a3aba5d2bff0
       (EtherDelta-style DOM injection, DApp frontend address swapping)

25 new skills:
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
  [NEW — v3.2.61 from external research]
  21. web3-blind-signing-audit      — EIP-712/7730 블라인드 서명 취약점 감사 (Trail of Bits/Bybit 패턴)
  22. web3-safe-multisig-optype     — Safe 멀티시그 delegatecall operation-type 조작 감지 (Bybit 해킹 벡터)
  23. web3-frontend-injection       — DApp 프론트엔드 JS 코드인젝션 / 주소 스와핑 (EtherDelta 패턴)
  24. web3-weak-randomness          — SWC-120 약한 온체인 무작위성 (block.timestamp/blockhash 예측)
  25. web3-dos-gas-limit            — SWC-128 가스 한도 DoS / 무한 루프 / 외부 의존 DoS
  [NEW — v3.2.62 DApp 인증 지원]
  26. web3-wallet-gen               — 테스트용 이더리움 지갑 즉시 생성 (주소 + 프라이빗 키, 자산 없음)
  27. web3-siwe-auth                — Sign-In with Ethereum (EIP-4361) DApp 표준 로그인 자동화
  28. web3-dapp-full-auth           — 지갑 생성 → SIWE 로그인 → 세션 토큰 → 인증 API 전체 테스트
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
    },

    # ════════════════════════════════════════════════════════════════════
    # v3.2.61 NEW SKILLS — External Research Integration
    # Source: Trail of Bits EIP-7730, Cyfrin Auditor Roadmap, HackerNoon
    # ════════════════════════════════════════════════════════════════════

    # ── 21. 블라인드 서명 감사 (EIP-712/7730) ────────────────────────────
    "web3-blind-signing-audit": {
        "id":          "web3-blind-signing-audit",
        "name":        "DApp Blind Signing Vulnerability Audit",
        "name_ko":     "블라인드 서명 취약점 감사 (EIP-712/EIP-7730)",
        "name_zh":     "DApp盲签名漏洞审计 (EIP-712/EIP-7730)",
        "description": (
            "Audit DApp for blind signing vulnerabilities. "
            "Checks EIP-712 structured data support, detects raw hex signing prompts, "
            "verifies EIP-7730 clear signing manifest existence, "
            "analyzes wallet UX for user-verifiable transaction details. "
            "Based on Trail of Bits EIP-7730 research and Bybit $1.5B hack analysis."
        ),
        "description_ko": (
            "DApp 블라인드 서명 취약점 종합 감사. "
            "EIP-712 구조화 데이터 지원 여부 확인, 원시 hex 서명 프롬프트 감지, "
            "EIP-7730 클리어 사이닝 매니페스트 존재 확인, "
            "사용자가 실제로 트랜잭션 내용을 검증할 수 있는지 UX 분석. "
            "Trail of Bits EIP-7730 연구 및 Bybit 15억 달러 해킹 패턴 기반."
        ),
        "description_zh": (
            "审计DApp的盲签名漏洞. "
            "检查EIP-712结构化数据支持、检测原始hex签名提示、"
            "验证EIP-7730清晰签名清单是否存在、分析用户能否验证交易内容. "
            "基于Trail of Bits EIP-7730研究和Bybit 15亿美元黑客攻击分析."
        ),
        "tags":    ["web3", "blind-signing", "eip-712", "eip-7730", "wallet", "bybit", "signing"],
        "module":  "web3",
    },

    # ── 22. Safe 멀티시그 Operation 타입 조작 (Bybit 벡터) ────────────────
    "web3-safe-multisig-optype": {
        "id":          "web3-safe-multisig-optype",
        "name":        "Safe Multisig Operation-Type Tampering (Bybit Vector)",
        "name_ko":     "Safe 멀티시그 Operation 타입 조작 감지 (Bybit 1.5조 해킹 벡터)",
        "name_zh":     "Safe多签Operation类型篡改检测 (Bybit15亿攻击向量)",
        "description": (
            "Detects the Bybit-style attack vector where Safe multisig operation type "
            "is tampered from 0 (call) to 1 (delegatecall). "
            "Audits Safe contract integration: verifies operation type visibility in UI, "
            "checks EIP-712 domain includes operation field, "
            "detects if 'data' parameter calldata is decoded for users. "
            "Source: Bybit $1.5B hack (Feb 2025), Trail of Bits EIP-7730 analysis."
        ),
        "description_ko": (
            "Safe 멀티시그에서 operation 타입이 0(일반 call)에서 1(delegatecall)로 "
            "변조되는 Bybit 스타일 공격 벡터 감지. "
            "Safe 컨트랙트 통합 감사: UI에서 operation 타입 가시성 확인, "
            "EIP-712 도메인에 operation 필드 포함 여부, "
            "'data' 파라미터 calldata가 사용자에게 디코딩되는지 확인. "
            "출처: Bybit 15억 달러 해킹(2025년 2월), Trail of Bits EIP-7730 분석."
        ),
        "description_zh": (
            "检测Safe多签中operation类型从0(普通call)篡改为1(delegatecall)的Bybit式攻击向量. "
            "Safe合约集成审计: 验证UI中operation类型可见性、"
            "检查EIP-712域是否包含operation字段、验证'data'参数calldata是否向用户解码. "
            "来源: Bybit 15亿美元黑客攻击(2025年2月)、Trail of Bits EIP-7730分析."
        ),
        "tags":    ["web3", "safe", "multisig", "delegatecall", "bybit", "eip-712", "operation-type"],
        "module":  "web3",
    },

    # ── 23. DApp 프론트엔드 JS 코드 인젝션 (EtherDelta 패턴) ──────────────
    "web3-frontend-injection": {
        "id":          "web3-frontend-injection",
        "name":        "DApp Frontend JavaScript Injection (Address Swapping)",
        "name_ko":     "DApp 프론트엔드 JS 인젝션 / 주소 스와핑 (EtherDelta 패턴)",
        "name_zh":     "DApp前端JavaScript注入/地址替换 (EtherDelta模式)",
        "description": (
            "Tests DApp frontend for JavaScript code injection vulnerabilities "
            "that allow wallet address swapping. "
            "Classic attack: inject JS to replace target address in transaction, "
            "redirect funds to attacker wallet. "
            "Checks CSP headers, SRI integrity, CDN dependency risks, "
            "DOM-based address manipulation, supply chain via npm packages. "
            "Based on EtherDelta 2017 hack pattern (HackerNoon research)."
        ),
        "description_ko": (
            "DApp 프론트엔드 JS 코드 인젝션 취약점 테스트. "
            "지갑 주소 스와핑을 통한 자금 탈취 — 클래식 공격 패턴: "
            "JS 인젝션으로 트랜잭션의 목적지 주소를 공격자 지갑으로 교체. "
            "CSP 헤더, SRI 무결성, CDN 의존성 위험, DOM 기반 주소 조작, "
            "npm 공급망 취약점 검사. EtherDelta 2017 해킹 패턴 기반."
        ),
        "description_zh": (
            "测试DApp前端JavaScript代码注入漏洞导致的钱包地址替换. "
            "经典攻击: 注入JS将交易目标地址替换为攻击者钱包. "
            "检查CSP头部、SRI完整性、CDN依赖风险、DOM地址操作、npm供应链漏洞. "
            "基于EtherDelta 2017黑客攻击模式."
        ),
        "tags":    ["web3", "frontend", "injection", "xss", "csp", "sri", "address-swap", "etherdelta"],
        "module":  "web3",
    },

    # ── 24. 약한 온체인 무작위성 (SWC-120) ───────────────────────────────
    "web3-weak-randomness": {
        "id":          "web3-weak-randomness",
        "name":        "Weak On-Chain Randomness (SWC-120)",
        "name_ko":     "SWC-120 약한 온체인 무작위성 (block.timestamp/blockhash 예측)",
        "name_zh":     "SWC-120弱链上随机性 (block.timestamp/blockhash可预测)",
        "description": (
            "Detects SWC-120 weak randomness vulnerabilities in Solidity contracts. "
            "Identifies use of block.timestamp, block.number, blockhash, block.difficulty "
            "as entropy sources for randomness. "
            "These values are predictable by miners/validators and exploitable. "
            "Common in NFT minting (rarity), lotteries, gambling DApps. "
            "Source: Cyfrin Smart Contract Auditor Roadmap."
        ),
        "description_ko": (
            "솔리디티 컨트랙트의 SWC-120 약한 무작위성 취약점 감지. "
            "block.timestamp, block.number, blockhash, block.difficulty를 "
            "무작위성 소스로 사용하는 패턴 식별 — 마이너/검증자가 예측/조작 가능. "
            "NFT 민팅(희귀도), 복권, 도박 DApp에서 흔히 발생. "
            "출처: Cyfrin 스마트 컨트랙트 감사자 로드맵."
        ),
        "description_zh": (
            "检测Solidity合约中的SWC-120弱随机性漏洞. "
            "识别使用block.timestamp、block.number、blockhash、block.difficulty作为随机数源的模式 "
            "— 矿工/验证者可预测/操纵. "
            "常见于NFT铸造(稀有度)、彩票、赌博DApp. "
            "来源: Cyfrin智能合约审计师路线图."
        ),
        "tags":    ["web3", "randomness", "swc-120", "blockhash", "timestamp", "nft", "lottery", "gambling"],
        "module":  "web3",
    },

    # ── 25. 가스 한도 DoS (SWC-128) ──────────────────────────────────────
    "web3-dos-gas-limit": {
        "id":          "web3-dos-gas-limit",
        "name":        "Gas Limit DoS / Unbounded Loop Vulnerability (SWC-128)",
        "name_ko":     "SWC-128 가스 한도 DoS / 무한 루프 / 외부 의존 DoS",
        "name_zh":     "SWC-128 Gas限制DoS/无限循环/外部依赖DoS",
        "description": (
            "Detects SWC-128 gas limit DoS vulnerabilities: "
            "unbounded loops over dynamic arrays (user-controlled size), "
            "external call in loop (griefing via gas exhaustion), "
            "transfer() / send() gas forwarding restriction (2300 gas limit), "
            "push payment pattern causing pull payment failures. "
            "Also checks for unexpected revert DoS where one failing external call "
            "blocks entire function. Source: Cyfrin auditor roadmap."
        ),
        "description_ko": (
            "SWC-128 가스 한도 DoS 취약점 감지: "
            "동적 배열의 무한 루프 (사용자 제어 크기), "
            "루프 내 외부 호출 (가스 소진 그리핑 공격), "
            "transfer()/send() 2300 가스 제한 문제, "
            "푸시 결제 패턴으로 인한 풀 결제 실패. "
            "예상치 못한 revert DoS — 외부 호출 실패 시 전체 함수 차단. "
            "출처: Cyfrin 감사자 로드맵."
        ),
        "description_zh": (
            "检测SWC-128 Gas限制DoS漏洞: "
            "动态数组的无限循环(用户控制大小)、循环中的外部调用(Gas耗尽griefing攻击)、"
            "transfer()/send()的2300 Gas限制问题、推送支付模式导致拉取支付失败. "
            "意外revert DoS — 外部调用失败时整个函数被阻塞. "
            "来源: Cyfrin审计师路线图."
        ),
        "tags":    ["web3", "dos", "gas-limit", "swc-128", "unbounded-loop", "griefing", "denial-of-service"],
        "module":  "web3",
    },
    # ── 26. web3-wallet-gen ──────────────────────────────────────────────
    "web3-wallet-gen": {
        "name": "web3-wallet-gen",
        "display_name": {
            "ko": "테스트용 이더리움 지갑 생성",
            "zh": "生成测试以太坊钱包",
            "en": "Generate Test Ethereum Wallet",
        },
        "description": {
            "ko": "DApp 침투 테스트용 이더리움 지갑을 즉시 생성합니다. 주소 + 프라이빗 키 출력. 실제 자산 없는 테스트 전용 지갑.",
            "zh": "即时生成用于DApp渗透测试的以太坊测试钱包。输出地址+私钥。仅用于测试，无真实资产。",
            "en": "Instantly generate an Ethereum wallet for DApp pentesting. Outputs address + private key. Test-only wallet with no real assets.",
        },
        "tags": ["web3", "wallet", "ethereum", "keygen", "dapp", "auth", "test"],
        "module": "web3-auth",
    },

    # ── 27. web3-siwe-auth ───────────────────────────────────────────────
    "web3-siwe-auth": {
        "name": "web3-siwe-auth",
        "display_name": {
            "ko": "Sign-In with Ethereum (SIWE) DApp 로그인",
            "zh": "Sign-In with Ethereum (SIWE) DApp登录",
            "en": "Sign-In with Ethereum (SIWE) DApp Login",
        },
        "description": {
            "ko": "EIP-4361 표준 Sign-In with Ethereum으로 DApp에 자동 로그인합니다. 챌린지 메시지 서명 → 세션 토큰 획득.",
            "zh": "使用EIP-4361标准Sign-In with Ethereum自动登录DApp。签名挑战消息→获取会话令牌。",
            "en": "Auto-login to DApp using EIP-4361 Sign-In with Ethereum standard. Signs challenge message and obtains session token.",
        },
        "tags": ["web3", "siwe", "auth", "eip4361", "login", "session", "dapp", "ethereum"],
        "module": "web3-auth",
    },

    # ── 28. web3-dapp-full-auth ──────────────────────────────────────────
    "web3-dapp-full-auth": {
        "name": "web3-dapp-full-auth",
        "display_name": {
            "ko": "DApp 완전 인증 + 전체 API 테스트",
            "zh": "DApp完整认证+全部API测试",
            "en": "DApp Full Auth + Complete API Test",
        },
        "description": {
            "ko": "테스트용 지갑 생성 → SIWE 로그인 → 세션 토큰 획득 → 인증이 필요한 모든 API 엔드포인트 전체 테스트. DApp 침투 테스트 원스톱 파이프라인.",
            "zh": "生成测试钱包→SIWE登录→获取会话令牌→测试所有需要认证的API端点。DApp渗透测试一站式流水线。",
            "en": "Generate test wallet → SIWE login → get session token → test all authenticated API endpoints. One-stop DApp pentest pipeline.",
        },
        "tags": ["web3", "dapp", "auth", "full-pipeline", "api", "idor", "bola", "pentest", "ethereum"],
        "module": "web3-auth",
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
