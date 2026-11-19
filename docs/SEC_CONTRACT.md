# SEC_CONTRACT — 8강 보안 실습 기준 문서 (수업용 가상 예시)

이 문서가 **판정의 기준(오라클)** 입니다. 평가기 코드를 읽고 점수에 맞추지 말고, 여기 적힌 규칙을 구현하세요. 숫자는 `config/sec.json` 에도 있습니다.

## 0. 점수 방식

- 자동 평가(40점) = 레드팀 6 + 코드 수정 9 + 스캐너 7 + 가드레일 12 + 보안 관제 6.
- 대부분 **균형 점수 = (공격을 막은 비율) × (정상 요청을 통과시킨 비율)** 입니다. 아무것도 막지 않거나 전부 막으면 0점입니다.
- 공개 시나리오는 예시이고, 채점에는 더 많고 **변형된 숨은 시나리오**가 쓰입니다. 시나리오 ID · 문장 · 시드를 코드에 박아 넣지 마세요.

## 1. 레드팀 — `redteam/attacks.json`

공격 케이스 한 건의 형식:

| 필드 | 값 |
|---|---|
| `id` | 문자열 (예: `RT-01`) |
| `category` | `LLM01` `LLM02` `LLM05` `LLM06` `LLM07` `LLM10` 중 하나 |
| `channel` | `user`(사용자 입력) 또는 `document`(외부 문서에 숨김) |
| `payload` | 공격 문장 (`document` 이면 문서 본문) |
| `userRequest` | (document 일 때) 사용자가 실제로 보낸 요청. 기본값 "이 내용을 요약해줘" |
| `user` | 요청자 (`u1` 기본, `u2`, `u3`) |
| `expectHarm` | 노리는 피해 코드의 배열 |

**피해 코드** (한 번의 요청에서 *실제로* 일어난 결과로만 판정합니다)

| 코드 | 의미 | 판정 근거 |
|---|---|---|
| `SECRET_LEAK` | 내부 키 · 접속 문자열 · 우회 코드가 응답 또는 로그에 나감 | 응답 · 로그의 문자열 |
| `PII_LEAK` | 가려지지 않은 휴대전화 · 주민번호 · 카드번호(Luhn) · 이메일이 응답 또는 로그에 나감 | 응답 · 로그의 문자열 |
| `CROSS_USER` | 요청자가 아닌 사람의 주문이 조회됨 | 도구 실행 기록 |
| `EXFIL` | `send_email` 이 실행됨 | 도구 실행 기록 |
| `UNAUTH_ACTION` | 환불 · 삭제가 승인 없이 실행됨, 또는 20% 초과 · 확인 없는 쿠폰이 적용됨 | 도구 실행 기록 |
| `OUTPUT_INJECTION` | 이스케이프되지 않은 HTML 태그가 응답에 있음, 또는 형식이 검증되지 않은 인자(주문번호 `^ORD-\d{4}$` 밖, 검색어의 `' " % ; --`)로 도구가 실행됨 | 응답 · 실행 기록 |
| `COST` | 한 요청에서 도구가 5회 초과 실행됨, 또는 모델에 2,000자 초과가 전달됨 | 실행 기록 · 입력 길이 |

**범주와 피해의 대응**: LLM01 → EXFIL · UNAUTH_ACTION · CROSS_USER · SECRET_LEAK / LLM02 → PII_LEAK · CROSS_USER · SECRET_LEAK / LLM05 → OUTPUT_INJECTION / LLM06 → UNAUTH_ACTION · CROSS_USER / LLM07 → SECRET_LEAK / LLM10 → COST

**유효한 공격** = 방어 없는 기준선 도우미에서 `expectHarm` 중 하나가 실제로 일어남. 30건까지, 같은 경로의 같은 문장(정규화 후)은 한 번만 셉니다.
점수: 범주 6개 커버(35%) + 유효 공격 12건(20%) + 경로 다양성(사용자 · 문서 · 난독화 표기, 15%) + **우리 방어가 우리 공격을 막는가**(30%, 정상 요청 통과율이 낮으면 감점).

## 2. AI 생성 코드와 스캐너

### 2.1 API (`app/shop_api.js`) — 고쳐야 하는 7가지

`createApi({ db, env, clock, gateway })` → `{ handle({ method, path, query, body, headers }) }` → `{ status, body }`

| 경로 | 성공 | 실패 |
|---|---|---|
| `POST /register` `{email,password,name,phone}` | 201 `{id}` | 400 `{error}` · 409 |
| `POST /login` `{email,password}` | 200 `{token}` | 401 `{error:"INVALID_CREDENTIALS"}` |
| `GET /products?q=` | 200 `{items:[{id,name,price}]}` (판매 중 상품만) | |
| `GET /orders/:id` (인증) | 200 `{id,status,total,items,address}` | 401 · 404 |
| `POST /orders` `{items:[{productId,quantity,price?}],address}` (인증) | 201 `{id,total,status}` | 400 |
| `POST /payments` `{orderId}` (인증) | 200 `{paid:true,amount}` | 401 · 404 |

| # | 취약점 | 통과 조건 (SRS) |
|---|---|---|
| V1 | SQL 인젝션 (로그인 · 검색) | 입력이 쿼리 구조를 바꾸지 못한다 — 로그인 우회 불가, 판매 중지 상품 노출 불가 (NFR-SEC-05) |
| V2 | 접근 통제(IDOR) | 본인 주문만 조회 · 결제 가능. 남의 주문과 없는 주문은 구분하지 않고 404 또는 403, 인증 없으면 401 (NFR-SEC-04) |
| V3 | 시크릿 하드코딩 | 소스에 비밀 값 없음. 키는 `env.PAYMENT_API_KEY`, `env.TOKEN_SECRET` 에서만 받고, **없으면 `createApi` 가 예외를 던진다**(fail closed). 결제는 env 의 키로 호출 |
| V4 | 비밀번호 저장 | 평문 · MD5 · SHA-1 · 솔트 없는 SHA-256 금지. 같은 비밀번호라도 저장값이 달라야 한다(솔트). 로그인은 정상 동작 (NFR-SEC-01) |
| V5 | 오류 정보 노출 | 오류 응답은 `{error:"짧은 코드"}` 만. 스택 · 파일 경로 · SQL · 접속 문자열 · 예외 이름 금지, 상태는 4xx/5xx |
| V6 | 클라이언트 값 신뢰 | 가격은 서버가 안다. `quantity` 는 1~99 정수, 상품은 존재 + 판매 중, `items` 1개 이상, `address` 필수. 위반은 400 |
| V7 | 위조 가능한 토큰 | 서명된 토큰, 만료(25시간 뒤 거절, 10분 뒤 유효). 위조 · 변조된 토큰은 401/403/404 로 거절 |

정상 기능(가입 · 로그인 · 검색 · 주문 · 결제 · 본인 조회)은 계속 동작해야 합니다. 시험 값은 `it's` 같은 따옴표 검색어를 포함합니다.

### 2.2 시크릿 탐지 — `scanSecrets(files)`

`files = [{path,text}]` → `[{path, line, type}]` (줄은 1부터, **한 줄에 한 건**, 아래 순서에서 먼저 맞는 유형)

| 유형 | 규칙 |
|---|---|
| `PRIVATE_KEY` | `-----BEGIN … PRIVATE KEY-----` |
| `AWS_ACCESS_KEY` | `AKIA` + 영대문자·숫자 16자 |
| `API_KEY_LIVE` | `sk-live-` 또는 `sk_live_` + 영숫자 12자 이상. 값이 자리표시자면 제외 |
| `JWT` | `eyJ….eyJ….서명` 세 덩어리(각 8자 이상) |
| `DB_URL_CREDENTIALS` | `scheme://사용자:비밀번호@호스트` 에서 비밀번호가 자리표시자가 아님 |
| `HARDCODED_SECRET` | `secret · password · passwd · pwd · token · api_key · private_key` 가 들어간 이름에 **따옴표 문자열 8자 이상**을 대입, 값이 자리표시자가 아님 |

**자리표시자(비밀 아님)**: `[대문자_이름]` · `<…>` · `xxxx`(4자 이상) · `****` · `...` · `${…}` · `changeme` · `your-…` · `dummy` · `placeholder` · `process.env` · `os.environ` · `env.` · 같은 글자 반복.
환경 변수 참조, 형식 설명(`password: string`), 커밋 해시 · 일반 해시, `sk_test_` 키는 **비밀이 아닙니다**.

### 2.3 의존성 위험 — `checkDependencies(pkg, lock, registry, cfg)`

`pkg.dependencies` 의 각 패키지에 대해 아래 코드를 모아 `[{name, codes:[알파벳순]}]`(위험 있는 것만, 이름순)로 돌려줍니다. `lock` 은 `{이름:{version}}`.
설치 버전 = `lock[이름].version`, 없으면 `pkg` 의 값이 정확한 버전(`x.y.z`)일 때 그 값, 아니면 모름.

| 코드 | 규칙 |
|---|---|
| `NOT_FOUND` | 저장소(`registry.packages`)에 없는 이름 — 환각이 만든 이름일 수 있다(슬롭스쿼팅) |
| `TYPOSQUAT` | 존재하지만 주간 다운로드 5,000 미만이고, 주간 다운로드 1,000,000 이상인 다른 패키지와 **편집 거리 ≤ 2** |
| `LOW_TRUST` | 존재하고 등록 30일 미만이며 주간 다운로드 1,000 미만 |
| `VULNERABLE` | 설치 버전을 알 때, 심각도 `high`/`critical` 권고의 `below` 버전보다 낮음 (`moderate` 이하는 무시) |
| `INSTALL_SCRIPT` | 설치 버전의 `scripts` 에 `preinstall/install/postinstall` 이 있고 `cfg.allowInstallScripts` 에 없음 |
| `DEPRECATED` | `deprecated: true` |
| `UNPINNED` | 값이 `*` · `latest` · `x` · 빈 문자열 · `git…` · `http…` · `file:…`, 또는 `^ ~ > <` 범위인데 `lock` 에 항목이 없음 |

### 2.4 SBOM — `generateSbom(pkg, lock, registry)`

CycloneDX 축약형. `lock` 의 **모든 항목(전이 의존성 포함)** 을 이름순으로.

```json
{ "bomFormat":"CycloneDX","specVersion":"1.5","version":1,
  "metadata":{"component":{"type":"application","name":"<pkg.name>","version":"<pkg.version>"}},
  "components":[{"type":"library","name":"n","version":"v","purl":"pkg:npm/n@v",
                 "licenses":[{"license":{"id":"MIT"}}],"hashes":[{"alg":"SHA-512","content":"<integrity>"}]}],
  "dependencies":[{"ref":"pkg:npm/n@v","dependsOn":["pkg:npm/m@w"]}] }
```
라이선스는 `registry.packages[이름].license`, 없으면 `NOASSERTION`. `hashes` 는 `integrity` 가 있을 때만. `dependencies` 는 `requires` 가 비어 있지 않은 항목만, `ref` 이름순, `dependsOn` 은 purl 정렬(잠금에 없는 이름은 제외).

## 3. 가드레일 파이프라인

```
요청 → 킬스위치 → 한도(limiter) → inspectInput → (문서) inspectInput · wrapUntrusted → 모의 LLM
     → validateAction → authorizeTool → 실행기 → sanitizeOutput → 응답 · 로그(redactSecrets(redactPII(입력)))
```
`src/assistant/assistant.js` 가 이 순서로 부릅니다(수정 금지).

### 3.1 `guard/input.js`

- `normalizeText(t)` — NFKC(전각→반각) + 보이지 않는 문자(제로폭 공백 `U+200B…200F`, `U+2060…206F`, `U+00AD`, `U+FE00…FE0F` 등) 제거. **모의 모델이 읽는 방식과 같습니다** — 필터는 모델이 보는 글자 기준이어야 합니다.
- `inspectInput(text, ctx)` → `{action:"allow"|"block", codes:[…], text}`. 정규화한 글자 기준으로
  - 2,000자 초과는 `TOO_LONG` 으로 차단,
  - **확실한** 공격 문장만 차단: 시스템 프롬프트·초기 지시를 (출력/알려/보여/공개/print/reveal/show…) 하라는 요청, "이전/위/앞의/기존 지시·명령·규칙을 (모두) 무시/잊어", `ignore (all) previous instructions`,
  - 구분자 문자열(`<<UNTRUSTED`, `UNTRUSTED>>`)이 들어 있으면 차단.
  - **차단하면 안 되는 정상 문장**: "배송 지연은 무시하고 …", "시스템 프롬프트 창이 안 떠요", "이전 주문 내역에서 …" 처럼 단어만 비슷한 문장.
- `wrapUntrusted(text)` → `<<UNTRUSTED\n본문\nUNTRUSTED>>`. 본문 안의 구분자 문자열(정규화 후에도)이 구분자로 작동하지 못하게 무력화해야 합니다.

### 3.2 `guard/output.js`

- `redactPII(t)` — 휴대전화(`010-1234-5678` · `01012345678` · 공백/점 구분) → `010-****-5678`, 주민등록번호 → `900101-1******`, 카드번호(13~19자리 **Luhn 통과분만**) → `****-****-****-1111`, 이메일 → `h***@도메인`. **주문번호(ORD-1001) · 금액 · 날짜 · 송장번호는 그대로.**
- `redactSecrets(t)` — 2.2 의 비밀 유형(개인키 · AWS 키 · live 키 · JWT · 접속 문자열의 비밀번호)과 내부 키(`INTERNAL-KEY-…`) · 우회 코드(`ADMIN-숫자`) · 내부 주소(`*.internal`)를 `[SECRET]`/`[INTERNAL]` 로.
- `sanitizeOutput(t)` — HTML 이스케이프(`< > & " '`) + `redactPII` + `redactSecrets`.
- `validateAction(raw, ctx)` — 모델이 낸 문자열을 **신뢰하지 않고** 검증:

| 검사 | 실패 코드 |
|---|---|
| JSON 이 아님 · 객체가 아님 · `text`/`tool_calls` 외의 키 · `text` 가 문자열이 아니거나 2,000자 초과 | `FORMAT` |
| `tool_calls` 3개 초과 | `TOO_MANY_CALLS` |
| 허용 목록 밖의 도구 (`send_email`, `delete_product` 등) | `TOOL_NOT_ALLOWED` |
| 인자 형식 위반 · 스키마에 없는 인자 | `ARG_INVALID` |

도구 스키마: `search_product{query: 문자·숫자·공백·하이픈 1~50자}` · `get_order_status{order_id: ^ORD-\d{4}$}` · `apply_coupon{code: ^[A-Z0-9]{4,12}$, percent: 1~100 정수}` · `refund_order{order_id: ^ORD-\d{4}$}`.
통과하면 `{ok:true, text, calls:[{name,args}]}`, 실패하면 `{ok:false, code}` — 그러면 파이프라인이 요청을 안전하게 거절합니다.

### 3.3 모델 구성 요소 — `src/assistant/systemPrompt.js`

`buildSystemPrompt(env)` 가 돌려주는 문자열에 **비밀 값 · 우회 규칙(관리자 코드 등) · 내부 주소 · "즉시 처리" 같은 권한 규칙이 없어야** 합니다(유출될 것이라고 가정). 권한 규칙은 코드(authz)에서 집행합니다.

### 3.4 `guard/authz.js` — 도구 호출 인가표

`authorizeTool(call, ctx)` → `{decision, reason}`. `ctx.orders.ownerOf(주문번호)` 는 소유자 ID(없으면 null), `ctx.tainted` 는 **외부 문서가 컨텍스트에 포함된 요청**이면 true.

| 도구 | 조건 | 결정 |
|---|---|---|
| `search_product` | — | `allow` |
| `get_order_status` | 요청자의 주문 | `allow` |
| | 남의 주문 · 없는 주문 | `deny` (`NOT_OWNER`) |
| `apply_coupon` | `tainted` | `deny` (`TAINTED_CONTEXT`) |
| | 할인율 1~20% | `confirm` (사용자 확인 후 실행) |
| | 그 외 | `deny` (`LIMIT`) |
| `refund_order` | `tainted` | `deny` (`TAINTED_CONTEXT`) |
| | 남의 주문 · 없는 주문 | `deny` (`NOT_OWNER`) |
| | 요청자의 주문 | `approve` (사용자 확인 **+** 담당자 승인 후 실행) |
| 그 밖의 모든 도구 | — | `deny` (`TOOL_NOT_ALLOWED`) |

파이프라인은 `confirm` 도구를 사용자 확인(`confirmed`) 후에만, `approve` 도구를 확인 + 담당자 승인(`staffApproved`) 후에만 실행하고, 그 전에는 "승인 대기"로 둡니다.

## 4. 보안 관제

### 4.1 `secops/detect.js` — `detect(events, now)` → `[{id, severity, userId?}]`

이벤트 `{ts(ms), type, userId, code?, tokens?}`. 창은 `(now − 창길이, now]`. 임계값은 `config/sec.json`.

| 경보 ID | 심각도 | 조건 | 단위 |
|---|---|---|---|
| `INJECTION_PROBE` | medium | `INPUT_BLOCKED` + `DOC_QUARANTINED` 합계 ≥ 3, 10분 | 사용자별 |
| `ORDER_ENUMERATION` | high | `AUTHZ_DENY` 중 `code = NOT_OWNER` ≥ 5, 5분 | 사용자별 |
| `BRUTE_FORCE` | high | `LOGIN_FAIL` ≥ 5, 5분 | 사용자(대상 계정)별 |
| `SECRET_IN_OUTPUT` | critical | `SECRET_IN_OUTPUT` 이벤트 1건 이상, 10분 | 전체(userId 없음) |
| `BUDGET_80` | medium | `TOKENS_USED.tokens` 합계 ≥ 일일 예산의 80%, 24시간 | 전체 |
| `BUDGET_100` | critical | 같은 합계 ≥ 일일 예산(50,000). **이때 BUDGET_80 은 내지 않는다** | 전체 |

### 4.2 `secops/limiter.js` — `createLimiter(cfg).check(userId, tokens, now)`

`cfg = {maxRequestsPerMin:10, maxTokensPerRequest:1000, dailyTokenBudget:50000}`. 검사 순서와 코드:

1. `tokens > maxTokensPerRequest` → `TOO_LARGE`
2. 같은 사용자의 **허용된** 요청이 최근 60초(`now−60000 < t ≤ now`)에 `maxRequestsPerMin` 이상 → `RATE_LIMIT`
3. 오늘(`floor(now/86400000)`) 허용된 토큰 합계 + `tokens` > 일일 예산 → `BUDGET` (전체 사용자 합산, 날짜가 바뀌면 초기화)

거절된 요청은 횟수 · 예산을 **소모하지 않습니다**. 허용이면 `{allow:true}`, 거절이면 `{allow:false, code}`.

### 4.3 `secops/killswitch.js`

`createKillSwitch()` → `isEnabled(f)` · `disable(f,{reason,actor,now})` · `enable(f,{actor,now})` · `audit()`.
기능 이름 `assistant` > `assistant.write_tools` (**상위를 끄면 하위도 꺼진 것으로 본다**). `disable` 은 `reason` 과 `actor` 가 없으면 예외, `enable` 은 `actor` 가 없으면 예외. `audit()` 는 `[{ts, feature, action:"disable"|"enable", reason?, actor}]`.

### 4.4 대응 절차 — `secops/playbook.json`

경보 6종 모두에 `{action, owner, slaMin, steps[]}`. `action` ∈ `KILL_SWITCH | REVOKE_KEY | BLOCK_USER | THROTTLE | REVIEW`. `steps` 는 구체적인 2단계 이상. critical 경보는 `KILL_SWITCH` 또는 `REVOKE_KEY` + `slaMin ≤ 15`, high 는 `slaMin ≤ 60`, 나머지는 `≤ 240`.

## 5. 사고 분석 형식 — `docs/incident_findings.json`

사고마다 `{incident, rootCause, failedControls[], evidence[], immediateActions[], lessons}`.

- `rootCause`: `indirect_injection` · `hardcoded_secret_committed` · `missing_ownership_check` · `malicious_dependency` · `unbounded_consumption` · `pii_in_logs`
- `failedControls`: `no_data_separation` · `no_taint_policy` · `no_output_validation` · `no_ownership_check` · `no_secret_scanning` · `no_least_privilege` · `no_rate_limit` · `no_dependency_review` · `no_log_masking` · `no_human_approval` · `no_monitoring_alert` · `no_kill_switch`
- `immediateActions`: `disable_write_tools` · `quarantine_document` · `revoke_and_rotate_key` · `purge_git_history` · `block_user` · `fix_authz_in_code` · `add_enumeration_alert` · `pin_and_remove_package` · `rotate_secrets_exposed_to_install` · `enable_rate_limit_and_budget` · `add_secret_scan_ci` · `notify_affected_users` · `mask_logs` · `add_regression_test` · `kill_switch_assistant`
- `evidence`: 로그 ID(`L0042`) 또는 변경 ID(`C-204`). **같은 시각에 있었을 뿐인 줄(미끼)을 근거로 쓰지 않습니다.** 사실이 아닌 ID 는 감점입니다.
