"""시크릿 유출 점검. gitleaks로 저장소의 커밋 이력 전체에서 API 키, 비밀번호 같은 값을 찾는다."""
import json
import os
import tempfile
from pathlib import Path

from projects.models import Target

from .base import ModuleResult, ScanError, ScanModule, last_lines


class SecretsModule(ScanModule):
    key = 'secrets'
    label = '시크릿 유출'
    kinds = (Target.Kind.REPO,)

    # gitleaks는 기본으로 '찾았음'과 '오류'를 둘 다 1로 끝낸다. 둘을 구분하려고 찾았을 때는 2로 끝내게 한다.
    LEAKS_FOUND = 2

    def run(self, target):
        path = target.config['path']
        if not os.path.isdir(path):
            raise ScanError(
                f'저장소 폴더를 찾을 수 없습니다: {path} '
                '(worker에 붙인 폴더 SELFSPAR_REPO_ROOT 안에 있어야 합니다.)'
            )

        # gitleaks는 git이 이력을 못 읽어도 오류를 로그에만 남기고 '유출 없음'(0)으로 끝난다.
        # 그러면 점검을 못 했는데 이상 없음으로 보이므로, 먼저 git이 이 폴더를 저장소로 읽는지 확인한다.
        repo_check = self.run_command(['git', '-C', path, 'rev-parse', '--git-dir'])
        if repo_check.returncode != 0:
            raise ScanError(f'git 저장소로 읽지 못했습니다: {path} {last_lines(repo_check.stderr)}')

        version = self.run_command(['gitleaks', 'version'])
        if version.returncode != 0:
            raise ScanError(f'gitleaks 버전을 확인하지 못했습니다. {last_lines(version.stderr)}')

        with tempfile.TemporaryDirectory() as workdir:
            report = Path(workdir) / 'report.json'
            # git: 지금 파일이 아니라 커밋 이력을 본다. 커밋하지 않은 .env 같은 파일은 읽지 않는다.
            # --redact: 결과 파일과 로그에 찾은 값을 그대로 쓰지 않고 REDACTED로 가린다.
            result = self.run_command([
                'gitleaks', 'git', path,
                '--report-format', 'json',
                '--report-path', str(report),
                '--redact',
                '--no-banner',
                '--no-color',
                '--exit-code', str(self.LEAKS_FOUND),
            ])
            if result.returncode not in (0, self.LEAKS_FOUND):
                raise ScanError(f'gitleaks 실행에 실패했습니다. {last_lines(result.stderr)}')
            raw_output = report.read_bytes()

        try:
            leaks = json.loads(raw_output)
        except ValueError:
            raise ScanError('gitleaks 결과 파일을 읽지 못했습니다.')

        return ModuleResult(
            finding_count=len(leaks),
            tool_version=version.stdout.decode().strip(),
            raw_output=raw_output,
        )
