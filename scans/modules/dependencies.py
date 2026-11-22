"""의존성 취약점 점검. trivy로 저장소의 잠금 파일(package-lock.json, gradle.lockfile, uv.lock 등)을 읽어
알려진 취약점(CVE)이 있는 라이브러리 버전을 찾는다."""
import hashlib
import json
import os
import tempfile
import tomllib
from pathlib import Path

from django.conf import settings

from findings.models import Finding
from projects.models import Target

from .base import FindingData, ModuleResult, ScanError, ScanModule, last_lines

# trivy가 읽는 잠금 파일(정확한 버전이 적힌 파일). 이 중 하나도 없으면 점검할 것이 없다.
# https://trivy.dev/latest/docs/coverage/language/
LOCK_FILES = {
    'package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lock',
    'gradle.lockfile', 'pom.xml',
    'uv.lock', 'poetry.lock', 'Pipfile.lock', 'requirements.txt',
    'go.mod', 'Cargo.lock', 'composer.lock', 'Gemfile.lock', 'packages.lock.json', 'pubspec.lock',
}
NPM_LOCKS = {'package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lock'}
PYTHON_LOCKS = {'uv.lock', 'poetry.lock', 'Pipfile.lock', 'requirements.txt'}
# 저장 칸 길이(Finding.fingerprint, location)
FIELD_LIMIT = 500


class DependenciesModule(ScanModule):
    key = 'dependencies'
    label = '의존성 취약점'
    kinds = (Target.Kind.REPO,)

    # trivy 심각도 → 우리 심각도. UNKNOWN은 아직 점수가 매겨지지 않은 취약점이다.
    SEVERITY = {
        'CRITICAL': Finding.Severity.CRITICAL,
        'HIGH': Finding.Severity.HIGH,
        'MEDIUM': Finding.Severity.MEDIUM,
        'LOW': Finding.Severity.LOW,
        'UNKNOWN': Finding.Severity.INFO,
    }
    # 저장소를 훑을 때 들어가지 않는 폴더. 설치·빌드 결과물이라 원본 설정이 아니다.
    # buildSrc는 Gradle 빌드 스크립트용 코드라 앱이 실행할 때 쓰는 의존성이 아니다.
    SKIP_DIRS = {
        '.git', 'node_modules', 'build', '.gradle', 'buildSrc', 'out', 'target', 'dist', '.venv', 'venv', '.idea',
    }
    TITLE_LIMIT = 300

    def run(self, target, cancelled):
        path = target.config['path']
        if not os.path.isdir(path):
            raise ScanError(
                f'저장소 폴더를 찾을 수 없습니다: {path} '
                '(worker에 붙인 폴더 SELFSPAR_REPO_ROOT 안에 있어야 합니다.)'
            )

        lock_count, unlocked = self.inspect(path)
        # trivy는 잠금 파일만 읽는다. 잠금 파일 없이 의존성 목록만 있는 프로젝트는 건너뛰고 '이상 없음'처럼 보이므로 미리 막는다.
        if unlocked:
            raise ScanError(
                '잠금 파일이 없어 의존성을 확인할 수 없는 프로젝트가 있습니다: ' + ', '.join(unlocked) + ' '
                '(Gradle은 dependencyLocking { lockAllConfigurations() }를 넣고 ./gradlew dependencies --write-locks, '
                'npm은 npm install, Python은 uv lock으로 잠금 파일을 만드세요.)'
            )
        # 의존성이 하나도 없는 잠금 파일은 trivy 결과에 나오지 않아서, 잠금 파일이 있는지는 trivy 결과가 아니라 직접 센다.
        if not lock_count:
            raise ScanError('의존성 잠금 파일(package-lock.json, gradle.lockfile, uv.lock 등)을 찾지 못했습니다.')

        cache_dir = str(settings.SELFSPAR_TRIVY_CACHE_DIR)
        with tempfile.TemporaryDirectory() as workdir:
            report = Path(workdir) / 'report.json'
            result = self.run_command([
                'trivy', 'fs', path,
                # 취약점만 본다. 시크릿은 시크릿 유출 모듈이 맡는다.
                '--scanners', 'vuln',
                '--format', 'json',
                '--output', str(report),
                '--cache-dir', cache_dir,
                # trivy 자체 제한 시간을 우리 제한 시간보다 짧게 두어, 끊기기 전에 trivy가 이유를 남기고 끝나게 한다.
                '--timeout', f'{self.timeout - 60}s',
                # 사용 통계를 Aqua로 보내지 않고, 새 버전 안내를 확인하러 접속하지 않는다.
                '--disable-telemetry',
                '--skip-version-check',
                '--quiet',
            ], cancelled)
            if result.returncode != 0:
                raise ScanError(f'trivy 실행에 실패했습니다. {last_lines(result.stderr)}')
            raw_output = report.read_bytes()

        try:
            data = json.loads(raw_output)
        except ValueError:
            raise ScanError('trivy 결과 파일을 읽지 못했습니다.')

        return ModuleResult(
            tool_version=self.tool_version(cache_dir, cancelled),
            raw_output=raw_output,
            findings=[
                self.to_finding(result['Target'], vuln)
                for result in data.get('Results') or []
                for vuln in result.get('Vulnerabilities') or []
            ],
        )

    def inspect(self, root):
        """저장소를 훑어서 (잠금 파일 수, 잠금 파일이 없는 프로젝트 목록)을 돌려준다.
        목록은 '저장소 기준 폴더 (의존성 목록 파일)' 모양이다. 예: api (build.gradle.kts)"""
        lock_count = 0
        unlocked = []
        # 폴더마다 그 폴더나 상위 폴더에 npm·Python 잠금 파일이 있는지. 모노레포는 잠금 파일이 맨 위에 하나만 있다.
        npm_locked = {}
        python_locked = {}
        for current, dirs, files in os.walk(root):
            # 목록을 직접 고쳐야 os.walk가 그 폴더 안으로 들어가지 않는다.
            dirs[:] = sorted(d for d in dirs if d not in self.SKIP_DIRS)
            names = set(files)
            parent = os.path.dirname(current)
            npm_locked[current] = bool(names & NPM_LOCKS) or npm_locked.get(parent, False)
            python_locked[current] = bool(names & PYTHON_LOCKS) or python_locked.get(parent, False)
            lock_count += len(names & LOCK_FILES)
            where = os.path.relpath(current, root)

            # Gradle 잠금 파일은 프로젝트(모듈)마다 그 폴더에 따로 생긴다.
            for build in ('build.gradle', 'build.gradle.kts'):
                if build in names and 'gradle.lockfile' not in names:
                    unlocked.append(f'{where} ({build})')
            if 'package.json' in names and not npm_locked[current] and self.npm_has_dependencies(current):
                unlocked.append(f'{where} (package.json)')
            if 'pyproject.toml' in names and not python_locked[current] and self.python_has_dependencies(current):
                unlocked.append(f'{where} (pyproject.toml)')
        return lock_count, unlocked

    def npm_has_dependencies(self, folder):
        """package.json에 의존성이 적혀 있는지. 스크립트만 있는 package.json은 잠금 파일이 없어도 된다."""
        try:
            data = json.loads((Path(folder) / 'package.json').read_text())
        except (OSError, ValueError):
            # 읽지 못하면 의존성이 있다고 보고 잠금 파일을 요구한다(놓치는 쪽보다 막는 쪽이 안전하다).
            return True
        return bool(data.get('dependencies') or data.get('devDependencies'))

    def python_has_dependencies(self, folder):
        """pyproject.toml에 의존성이 적혀 있는지. 도구 설정(ruff 등)만 있는 pyproject.toml은 잠금 파일이 없어도 된다."""
        try:
            data = tomllib.loads((Path(folder) / 'pyproject.toml').read_text())
        except (OSError, ValueError):
            return True
        poetry = data.get('tool', {}).get('poetry', {})
        return bool(data.get('project', {}).get('dependencies') or poetry.get('dependencies'))

    def tool_version(self, cache_dir, cancelled):
        """trivy 버전과 취약점 DB 날짜. DB가 언제 것이냐에 따라 같은 코드도 결과가 달라지므로 둘 다 남긴다. 예: 0.76.2 (DB 2026-11-20)"""
        result = self.run_command(['trivy', 'version', '--format', 'json', '--cache-dir', cache_dir], cancelled)
        if result.returncode != 0:
            raise ScanError(f'trivy 버전을 확인하지 못했습니다. {last_lines(result.stderr)}')
        try:
            info = json.loads(result.stdout)
            db_date = (info.get('VulnerabilityDB') or {}).get('UpdatedAt', '')[:10]
            return f"{info['Version']} (DB {db_date})" if db_date else info['Version']
        except (ValueError, KeyError):
            raise ScanError('trivy 버전 정보를 읽지 못했습니다.')

    def to_finding(self, file, vuln):
        """trivy 취약점 한 건을 발견 하나로 바꾼다."""
        package = vuln['PkgName']
        installed = vuln['InstalledVersion']
        fixed = vuln.get('FixedVersion', '')
        vuln_id = vuln['VulnerabilityID']
        if fixed:
            evidence = f'{package} {installed} → {fixed}에서 고침'
        else:
            evidence = f'{package} {installed} (아직 고친 버전 없음)'
        # 같은 파일의 같은 패키지·버전에서 같은 취약점이면 같은 발견이다. 버전을 올리면 새 발견이 아니라 사라진다.
        fingerprint = f'{file}:{package}:{installed}:{vuln_id}'
        if len(fingerprint) > FIELD_LIMIT:
            # 경로가 아주 깊어 칸에 안 들어가면 지문(해시)으로 줄인다. 같은 값이면 늘 같은 해시라 중복 판단은 그대로다.
            fingerprint = 'sha256:' + hashlib.sha256(fingerprint.encode()).hexdigest()
        return FindingData(
            fingerprint=fingerprint,
            rule_id=vuln_id,
            title=(vuln.get('Title') or vuln_id)[:self.TITLE_LIMIT],
            severity=self.SEVERITY.get(vuln.get('Severity'), Finding.Severity.INFO),
            location=file[:FIELD_LIMIT],
            evidence=evidence,
            extra={
                'package': package,
                'installed_version': installed,
                'fixed_version': fixed,
                'url': vuln.get('PrimaryURL', ''),
            },
        )
