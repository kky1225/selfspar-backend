# selfspar

내 서비스를 배포 전에 스스로 공격해 보고 보안을 점검하는 로컬 대시보드.
"나 자신과 스파링한다"는 뜻이다. 내가 소유한 서비스에만 쓴다.

## 실행

1. 프로젝트 폴더에 `.env` 파일을 만든다. git에는 올리지 않는다.

   | 이름 | 설명 |
   |---|---|
   | `DJANGO_SECRET_KEY` | Django 비밀 키. 임의의 긴 문자열 |
   | `DJANGO_DEBUG` | `1`이면 디버그 모드 |
   | `POSTGRES_DB` | DB 이름 (예: `selfspar`) |
   | `POSTGRES_USER` | DB 사용자 (예: `selfspar`) |
   | `POSTGRES_PASSWORD` | DB 비밀번호. 임의의 문자열 |
   | `SELFSPAR_ENCRYPTION_KEY` | 테스트 계정 비밀번호 암호화 키. 잃어버리면 저장한 비밀번호를 풀 수 없다 |
   | `SELFSPAR_REPO_ROOT` | 점검할 저장소들이 있는 내 컴퓨터 폴더 (예: `/Users/me/IdeaProjects`). worker에 읽기 전용으로 붙는다 |

   암호화 키는 아래 명령으로 만든다.

   ```bash
   python3 -c "import base64, os; print(base64.urlsafe_b64encode(os.urandom(32)).decode())"
   ```

2. 컨테이너를 띄우고 DB 테이블을 만든다.

   ```bash
   docker compose up -d --build
   docker compose exec web python manage.py migrate
   ```

3. 화면은 프론트엔드 저장소(selfspar-frontend)를 실행해서 http://localhost:5180 으로 접속한다.
   이 서버(`127.0.0.1:8800`)에는 API(`/api/`)와 관리자 화면(`/admin/`)만 있다.

## 테스트

점검 모듈 테스트는 실제 점검 도구(git, gitleaks)를 실행하므로, 도구가 들어 있는 `worker`에서 실행한다. `web`에는 도구가 없어서 해당 테스트가 실패한다.

```bash
docker compose exec worker python manage.py test
```

## 의존성 바꾸기

의존성은 [uv](https://docs.astral.sh/uv/)로 관리한다. `pyproject.toml`에 적고, 간접 의존성까지 포함한 정확한 버전과 해시는 `uv.lock`에 고정한다. 두 파일 모두 git에 올린다.

```bash
uv add 패키지이름
```

```bash
uv add --dev 패키지이름
```

`pyproject.toml`을 직접 고쳤다면 잠금 파일을 다시 만든다.

```bash
uv lock
```

바꾼 뒤에는 이미지를 다시 만든다. `uv.lock`이 `pyproject.toml`과 맞지 않으면 빌드가 실패한다.

```bash
docker compose up -d --build
```

## 구성

- `web`: Django 6.1 + DRF (Python 3.14). 내 컴퓨터의 `127.0.0.1:8800`에만 열린다. git과 점검 도구가 없는 이미지를 쓴다.
- `worker`: 점검을 실제로 실행한다(Celery). git과 점검 도구(gitleaks)가 들어 있다. `.py` 파일을 고치면 자동으로 다시 뜬다(watchfiles). 이때 실행 중이던 점검은 중단되고 '실행 중'으로 남아, 그 프로젝트의 새 점검이 막힌다. 관리자 화면(`/admin/`)에서 그 점검의 상태를 완료로 바꾸면 풀린다.
- `redis`: `web`이 점검 요청을 넣고 `worker`가 꺼내 가는 곳. 외부로 열리지 않는다.
- `db`: PostgreSQL 18. 외부로 열리지 않고 `web`, `worker`에서만 접속한다.

## 점검 모듈

| 모듈 | 대상 | 도구 | 확인하는 것 |
|---|---|---|---|
| 시크릿 유출 | 저장소 | gitleaks 8.30.1 | 커밋 이력 전체에 남은 API 키, 비밀번호. 결과에는 찾은 값을 가려서(REDACTED) 남긴다 |
