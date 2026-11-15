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

2. 컨테이너를 띄우고 DB 테이블을 만든다.

   ```bash
   docker compose up -d --build
   docker compose exec web python manage.py migrate
   ```

3. 화면은 프론트엔드 저장소(selfspar-frontend)를 실행해서 http://localhost:5180 으로 접속한다.
   이 서버(`127.0.0.1:8800`)에는 API(`/api/`)와 관리자 화면(`/admin/`)만 있다.

## 구성

- `web`: Django 6.1 + DRF (Python 3.13). 내 컴퓨터의 `127.0.0.1:8800`에만 열린다.
- `db`: PostgreSQL 18. 외부로 열리지 않고 `web`에서만 접속한다.
