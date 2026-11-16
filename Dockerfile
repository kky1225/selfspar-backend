FROM python:3.13-slim

# .pyc 파일을 만들지 않고, 로그를 버퍼 없이 바로 출력한다.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# 점검 도구가 쓰는 프로그램. 시크릿 점검 도구(gitleaks)는 커밋 이력을 읽을 때 git을 쓴다.
RUN apt-get update \
    && apt-get install -y --no-install-recommends git curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# 점검하는 저장소는 내 컴퓨터 폴더를 읽기 전용으로 붙인 것이라 파일 주인이 컨테이너 사용자와 다르다.
# git은 주인이 다른 저장소를 기본으로 거부해서, 붙인 저장소를 읽을 수 있게 허용한다.
RUN git config --system --add safe.directory '*'

# 시크릿 유출 점검 도구. 버전을 고정하고, 내려받은 파일이 공식 체크섬과 같은지 확인한 뒤 설치한다.
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
    && tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks \
    && rm /tmp/gitleaks.tar.gz

WORKDIR /app

# 의존성을 먼저 설치해 두면 코드만 바뀌었을 때 이 단계는 캐시를 재사용한다.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# root가 아닌 일반 사용자로 실행한다. 앱이 뚫려도 컨테이너 안 권한이 작다.
RUN useradd --create-home selfspar
# 점검 도구의 원본 결과를 보관하는 폴더. docker-compose.yml의 볼륨이 처음 만들어질 때 이 주인을 물려받는다.
RUN mkdir -p /data/scan-results && chown selfspar /data/scan-results
USER selfspar

EXPOSE 8000
