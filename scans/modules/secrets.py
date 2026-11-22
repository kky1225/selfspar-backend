"""시크릿 유출 점검. gitleaks로 저장소의 커밋 이력 전체에서 API 키, 비밀번호 같은 값을 찾는다."""
import json
import os
import tempfile
from pathlib import Path

from findings.models import Finding
from projects.models import Target

from .base import FindingData, ModuleResult, ScanError, ScanModule, last_lines


class SecretsModule(ScanModule):
    key = 'secrets'
    label = '시크릿 유출'
    kinds = (Target.Kind.REPO,)

    # gitleaks는 기본으로 '찾았음'과 '오류'를 둘 다 1로 끝낸다. 둘을 구분하려고 찾았을 때는 2로 끝내게 한다.
    LEAKS_FOUND = 2
    # 근거 줄을 저장할 때 남기는 최대 글자 수
    EVIDENCE_LIMIT = 300

    def run(self, target, cancelled):
        path = target.config['path']
        if not os.path.isdir(path):
            raise ScanError(
                f'저장소 폴더를 찾을 수 없습니다: {path} '
                '(worker에 붙인 폴더 SELFSPAR_REPO_ROOT 안에 있어야 합니다.)'
            )

        # gitleaks는 git이 이력을 못 읽어도 오류를 로그에만 남기고 '유출 없음'(0)으로 끝난다.
        # 그러면 점검을 못 했는데 이상 없음으로 보이므로, 먼저 git이 이 폴더를 저장소로 읽는지 확인한다.
        repo_check = self.run_command(['git', '-C', path, 'rev-parse', '--git-dir'], cancelled)
        if repo_check.returncode != 0:
            raise ScanError(f'git 저장소로 읽지 못했습니다: {path} {last_lines(repo_check.stderr)}')

        version = self.run_command(['gitleaks', 'version'], cancelled)
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
            ], cancelled)
            if result.returncode not in (0, self.LEAKS_FOUND):
                raise ScanError(f'gitleaks 실행에 실패했습니다. {last_lines(result.stderr)}')
            raw_output = report.read_bytes()

        try:
            leaks = json.loads(raw_output)
        except ValueError:
            raise ScanError('gitleaks 결과 파일을 읽지 못했습니다.')

        return ModuleResult(
            tool_version=version.stdout.decode().strip(),
            raw_output=raw_output,
            findings=[self.to_finding(leak) for leak in leaks],
        )

    def to_finding(self, leak):
        """gitleaks 결과 한 건을 발견 하나로 바꾼다."""
        # --redact를 붙였으면 찾은 값은 REDACTED로 바뀌어 있다. 아니라면 진짜 값이 DB에 들어가므로 저장하지 않는다.
        if leak.get('Secret') != 'REDACTED':
            raise ScanError('gitleaks 결과에 가려지지 않은 값이 있어 저장하지 않았습니다.')
        return FindingData(
            fingerprint=leak['Fingerprint'],
            rule_id=leak['RuleID'],
            title=leak.get('Description') or leak['RuleID'],
            # 시크릿 유출은 판정 기준에 따라 모두 치명으로 본다.
            severity=Finding.Severity.CRITICAL,
            location=f"{leak['File']}:{leak['StartLine']}",
            # 찾은 값이 있던 줄. 값 자리는 REDACTED로 가려져 있다. 너무 긴 줄은 앞부분만 남긴다.
            evidence=leak.get('Match', '')[:self.EVIDENCE_LIMIT],
            # 커밋 작성자, 이메일, 커밋 메시지는 화면에 필요 없어서 저장하지 않는다(원본 파일에는 남는다).
            extra={'commit': leak.get('Commit', ''), 'date': leak.get('Date', '')},
        )
