# syntax=docker/dockerfile:1

# 단계(stage)를 나눠서 최종 이미지에는 실행에 필요한 것만 남긴다.
#   python-deps    : uv로 파이썬 의존성을 /opt/venv에 설치한다 (uv는 여기에만 있다)
#   tools-download : 점검 도구를 내려받고 체크섬을 확인한다 (curl은 여기에만 있다)
#   runtime        : web·worker 공통 바탕 (파이썬 + 의존성 + 일반 사용자)
#   web            : API 서버. git·점검 도구가 없다
#   worker         : 점검 실행. git + 점검 도구가 있다
# docker-compose.yml이 서비스마다 target으로 web 또는 worker를 고른다.

# 이미지는 태그와 함께 digest(내용의 지문)로 고정한다. 태그는 나중에 다른 내용을 가리키게 바뀔 수 있다.
ARG PYTHON_IMAGE=python:3.14.10-slim-trixie@sha256:9aaa474097d094040649f2162a627c0049b408f52138d980916788d80f04802f


FROM ghcr.io/astral-sh/uv:0.13.8@sha256:5cc1805e2426484abca4ad46ea783bab281fdb225fd82d8ce6d66a81254bac85 AS uv


FROM ${PYTHON_IMAGE} AS python-deps

COPY --from=uv /uv /bin/uv

# UV_COMPILE_BYTECODE: 설치할 때 .pyc를 미리 만들어 둬서 시작이 빠르다.
# UV_LINK_MODE: 캐시와 설치 위치가 다른 파일 시스템이라 링크 대신 복사한다.
# UV_PYTHON_DOWNLOADS: 파이썬을 따로 내려받지 않고 이미지에 있는 파이썬을 쓴다.
# UV_PROJECT_ENVIRONMENT: 가상환경을 /app 밖에 만든다. compose가 /app에 코드 폴더를 붙여도 가려지지 않는다.
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=0 \
    UV_PROJECT_ENVIRONMENT=/opt/venv

# 기본값은 개발용 의존성(dev 그룹)을 빼고 설치한다. 로컬 개발은 docker-compose.yml에서 0으로 넘긴다.
ARG UV_NO_DEV=1

WORKDIR /app

# --locked: uv.lock이 pyproject.toml과 맞지 않으면 빌드를 실패시킨다(잠금 파일과 다른 버전이 깔리지 않게).
# --no-install-project: 이 프로젝트는 패키지가 아니라서 의존성만 설치한다.
# 두 파일만 잠깐 붙여서 쓰므로 코드만 바뀌었을 때는 이 단계 캐시를 그대로 쓴다.
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    uv sync --locked --no-install-project


FROM ${PYTHON_IMAGE} AS tools-download

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# 시크릿 유출 점검 도구. 버전을 고정하고, 내려받은 파일이 공식 체크섬과 같은지 확인한다.
# TARGETARCH는 Docker가 채워 준다(Apple 칩 Mac이면 arm64).
ARG GITLEAKS_VERSION=8.30.1
ARG TARGETARCH
RUN case "$TARGETARCH" in \
      amd64) arch=x64; sum=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb ;; \
      arm64) arch=arm64; sum=e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080 ;; \
      *) echo "지원하지 않는 CPU입니다: $TARGETARCH"; exit 1 ;; \
    esac \
    && curl -fsSL -o /tmp/gitleaks.tar.gz \
       "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${arch}.tar.gz" \
    && echo "${sum}  /tmp/gitleaks.tar.gz" | sha256sum -c - \
    # --no-same-owner: 압축 파일에 적힌 만든 사람의 uid 대신 root 소유로 푼다.
    && tar -xzf /tmp/gitleaks.tar.gz --no-same-owner -C /usr/local/bin gitleaks \
    && rm /tmp/gitleaks.tar.gz


FROM ${PYTHON_IMAGE} AS runtime

# .pyc 파일을 만들지 않고(코드 폴더에 생기지 않게), 로그를 버퍼 없이 바로 출력한다.
# PATH 앞에 가상환경을 두어 python, celery 같은 명령이 /opt/venv의 것으로 실행된다.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH"

# root가 아닌 일반 사용자로 실행한다. 앱이 뚫려도 컨테이너 안 권한이 작다.
RUN useradd --create-home selfspar

# 의존성은 root 소유로 둔다. 실행 사용자(selfspar)는 읽기만 할 수 있어 설치된 패키지를 바꿀 수 없다.
COPY --from=python-deps /opt/venv /opt/venv

WORKDIR /app


FROM runtime AS web

COPY . .

USER selfspar
EXPOSE 8000


FROM runtime AS worker

# 시크릿 점검 도구(gitleaks)는 커밋 이력을 읽을 때 git을 쓴다.
RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

# 점검하는 저장소는 내 컴퓨터 폴더를 읽기 전용으로 붙인 것이라 파일 주인이 컨테이너 사용자와 다르다.
# git은 주인이 다른 저장소를 기본으로 거부해서, 붙인 저장소를 읽을 수 있게 허용한다.
RUN git config --system --add safe.directory '*'

COPY --from=tools-download /usr/local/bin/gitleaks /usr/local/bin/gitleaks

# 점검 도구의 원본 결과를 보관하는 폴더. docker-compose.yml의 볼륨이 처음 만들어질 때 이 주인을 물려받는다.
RUN mkdir -p /data/scan-results && chown selfspar /data/scan-results

COPY . .

USER selfspar
