import json
import os
import secrets
import string
import subprocess
import unittest
import tempfile
from pathlib import Path
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.db import IntegrityError
from django.test import Client, TestCase, override_settings
from django.urls import reverse

from projects.models import Project, Target

from .models import ModuleRun, Scan
from .modules import MODULES_BY_KEY
from .modules.base import FindingData, ModuleResult, ScanError, ScanModule
from .modules.dependencies import DependenciesModule
from .modules.secrets import SecretsModule
from .tasks import run_scan


def make_target(project, name='로컬', kind='repo', path='/repo'):
    config = {'path': path} if kind == 'repo' else {'base_url': 'http://localhost:8081', 'token_location': 'header'}
    return Target.objects.create(project=project, name=name, kind=kind, environment='local', config=config)


def finding_data(fingerprint, location='settings.py:1'):
    return FindingData(
        fingerprint=fingerprint, rule_id='generic-api-key', title='Generic API Key', severity='critical',
        location=location, evidence='api_key = REDACTED', extra={'commit': 'abc123'},
    )


class ScanApiTestCase(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user('tester', password='correct-horse-battery')
        self.client.force_login(self.user)
        self.project = Project.objects.create(name='karaoke')
        self.repo = make_target(self.project, '로컬', 'repo')
        self.api = make_target(self.project, '관리자', 'api')
        # 테스트에서는 Redis에 실제로 보내지 않는다. 보내려고 했는지만 확인한다.
        patcher = patch('scans.api_views.run_scan')
        self.run_scan = patcher.start()
        self.addCleanup(patcher.stop)

    def start(self, project=None, client=None):
        url = reverse('api_scan_list', args=[(project or self.project).pk])
        return (client or self.client).post(url, content_type='application/json')


class ScanCreateApiTests(ScanApiTestCase):
    def test_전체_점검을_시작하면_201이고_해당하는_칸만_만든다(self):
        response = self.start()

        self.assertEqual(response.status_code, 201)
        scan = Scan.objects.get()
        self.assertEqual(scan.status, Scan.Status.QUEUED)
        # 저장소 대상 × (시크릿, 의존성) 두 칸만 생긴다. API 대상에는 아직 해당하는 모듈이 없다.
        self.assertEqual(
            list(scan.runs.values_list('target', 'module')),
            [(self.repo.pk, 'secrets'), (self.repo.pk, 'dependencies')],
        )
        data = response.json()
        self.assertEqual(data['id'], scan.pk)
        self.assertEqual(data['status_label'], '대기')
        self.assertEqual(
            data['modules'],
            [{'key': 'secrets', 'label': '시크릿 유출'}, {'key': 'dependencies', 'label': '의존성 취약점'}],
        )

    def test_만든_점검을_worker에_보낸다(self):
        self.start()

        self.run_scan.delay.assert_called_once_with(Scan.objects.get().pk)

    def test_실행_중인_점검이_있으면_409이고_새로_만들지_않는다(self):
        for active in Scan.ACTIVE:
            with self.subTest(status=active):
                Scan.objects.all().delete()
                Scan.objects.create(project=self.project, status=active)

                response = self.start()

                self.assertEqual(response.status_code, 409)
                self.assertEqual(Scan.objects.count(), 1)
                self.run_scan.delay.assert_not_called()

    def test_끝난_점검만_있으면_새로_시작할_수_있다(self):
        Scan.objects.create(project=self.project, status=Scan.Status.DONE)

        self.assertEqual(self.start().status_code, 201)

    def test_다른_프로젝트의_점검은_상관없다(self):
        other = Project.objects.create(name='investfeed')
        Scan.objects.create(project=other, status=Scan.Status.RUNNING)

        self.assertEqual(self.start().status_code, 201)

    def test_점검할_수_있는_대상이_없으면_400이다(self):
        project = Project.objects.create(name='API만 있음')
        make_target(project, '관리자', 'api')

        response = self.start(project)

        self.assertEqual(response.status_code, 400)
        self.assertIn('detail', response.json())
        self.assertFalse(Scan.objects.filter(project=project).exists())

    def test_worker에_보내지_못하면_503이고_점검을_남기지_않는다(self):
        self.run_scan.delay.side_effect = OSError('redis 연결 실패')

        with self.assertLogs('scans.api_views', 'ERROR'):
            response = self.start()

        self.assertEqual(response.status_code, 503)
        self.assertFalse(Scan.objects.exists())
        self.assertFalse(ModuleRun.objects.exists())

    def test_DB도_끝나지_않은_점검을_프로젝트마다_하나만_허용한다(self):
        Scan.objects.create(project=self.project, status=Scan.Status.RUNNING)

        with self.assertRaises(IntegrityError):
            Scan.objects.create(project=self.project)

    def test_없는_프로젝트는_404이다(self):
        response = self.client.post(reverse('api_scan_list', args=[9999]))

        self.assertEqual(response.status_code, 404)

    def test_로그인하지_않으면_403이다(self):
        response = self.start(client=Client())

        self.assertEqual(response.status_code, 403)
        self.assertFalse(Scan.objects.exists())

    def test_CSRF_토큰_없이는_시작할_수_없다(self):
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.user)

        response = self.start(client=client)

        self.assertEqual(response.status_code, 403)
        self.assertFalse(Scan.objects.exists())


class ScanListApiTests(ScanApiTestCase):
    def test_최근_점검부터_칸_상태별_개수와_발견_건수를_함께_돌려준다(self):
        old = Scan.objects.create(project=self.project, status=Scan.Status.DONE)
        ModuleRun.objects.create(
            scan=old, target=self.repo, module='secrets', status=ModuleRun.Status.FOUND, finding_count=2,
        )
        ModuleRun.objects.create(scan=old, target=self.api, module='other', status=ModuleRun.Status.FAILED)
        new = Scan.objects.create(project=self.project)
        ModuleRun.objects.create(scan=new, target=self.repo, module='secrets', status=ModuleRun.Status.PASSED)
        ModuleRun.objects.create(scan=new, target=self.api, module='other', status=ModuleRun.Status.RUNNING)

        response = self.client.get(reverse('api_scan_list', args=[self.project.pk]))

        self.assertEqual(response.status_code, 200)
        first, second = response.json()
        self.assertEqual(first['id'], new.pk)
        self.assertEqual(
            (first['run_count'], first['finished_run_count'], first['finding_count'], first['failed_count']),
            (2, 1, 0, 0),
        )
        self.assertEqual(second['id'], old.pk)
        # 발견은 칸 수(1)가 아니라 건수(2)를 센다.
        self.assertEqual(
            (second['run_count'], second['finished_run_count'], second['finding_count'], second['failed_count']),
            (2, 2, 2, 1),
        )

    def test_칸이_없는_점검의_발견_건수는_0이다(self):
        Scan.objects.create(project=self.project)

        response = self.client.get(reverse('api_scan_list', args=[self.project.pk]))

        self.assertEqual(response.json()[0]['finding_count'], 0)

    def test_다른_프로젝트의_점검은_보이지_않는다(self):
        other = Project.objects.create(name='investfeed')
        Scan.objects.create(project=other)

        response = self.client.get(reverse('api_scan_list', args=[self.project.pk]))

        self.assertEqual(response.json(), [])


class ScanDetailApiTests(ScanApiTestCase):
    def test_격자에_필요한_모듈_대상_칸을_돌려준다(self):
        scan = Scan.objects.create(project=self.project)
        ModuleRun.objects.create(
            scan=scan, target=self.repo, module='secrets', status=ModuleRun.Status.FOUND,
            finding_count=2, tool_version='8.30.1', raw_output_path='scan-1/run-1-secrets.json',
        )

        response = self.client.get(reverse('api_scan_detail', args=[scan.pk]))

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data['project'], {'id': self.project.pk, 'name': 'karaoke'})
        self.assertEqual([target['name'] for target in data['targets']], ['로컬', '관리자'])
        self.assertEqual(data['targets'][0]['kind_label'], '저장소')
        run = data['runs'][0]
        self.assertEqual(run['target'], self.repo.pk)
        self.assertEqual(run['status_label'], '발견')
        self.assertEqual(run['finding_count'], 2)
        # 서버 안의 파일 경로는 화면에 보낼 필요가 없다.
        self.assertNotIn('raw_output_path', run)

    def test_점검을_시작한_뒤에_등록한_대상은_빼고_보낸다(self):
        scan = Scan.objects.create(project=self.project)
        make_target(self.project, '나중에 등록', 'repo')

        response = self.client.get(reverse('api_scan_detail', args=[scan.pk]))

        self.assertEqual([target['name'] for target in response.json()['targets']], ['로컬', '관리자'])

    def test_없는_점검은_404이다(self):
        self.assertEqual(self.client.get(reverse('api_scan_detail', args=[9999])).status_code, 404)

    def test_로그인하지_않으면_403이다(self):
        scan = Scan.objects.create(project=self.project)

        self.assertEqual(Client().get(reverse('api_scan_detail', args=[scan.pk])).status_code, 403)


class FakeModule(ScanModule):
    """정해 둔 결과를 돌려주거나 정해 둔 오류를 일으키는 가짜 모듈"""

    kinds = (Target.Kind.REPO,)

    def __init__(self, key, result=None, error=None):
        self.key = key
        self.result = result
        self.error = error

    def run(self, target):
        if self.error:
            raise self.error
        return self.result


class RunScanTests(TestCase):
    def setUp(self):
        self.results_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.results_dir.cleanup)
        settings_patch = override_settings(SELFSPAR_SCAN_RESULTS_DIR=Path(self.results_dir.name))
        settings_patch.enable()
        self.addCleanup(settings_patch.disable)

        fakes = {
            'found': FakeModule('found', ModuleResult('1.0.0', b'[1, 2, 3]', [finding_data(f'fp-{n}') for n in range(3)])),
            'passed': FakeModule('passed', ModuleResult('1.0.0', b'[]')),
            'scan_error': FakeModule('scan_error', error=ScanError('저장소 폴더를 찾을 수 없습니다')),
            'crash': FakeModule('crash', error=KeyError('path')),
        }
        modules_patch = patch.dict(MODULES_BY_KEY, fakes)
        modules_patch.start()
        self.addCleanup(modules_patch.stop)

        project = Project.objects.create(name='karaoke')
        self.target = make_target(project)
        self.scan = Scan.objects.create(project=project)

    def make_run(self, module):
        return ModuleRun.objects.create(scan=self.scan, target=self.target, module=module)

    def test_찾으면_발견이고_원본_결과를_파일로_보관한다(self):
        run = self.make_run('found')

        run_scan(self.scan.pk)

        run.refresh_from_db()
        self.assertEqual(run.status, ModuleRun.Status.FOUND)
        self.assertEqual(run.finding_count, 3)
        self.assertEqual(run.tool_version, '1.0.0')
        self.assertIsNotNone(run.started_at)
        self.assertIsNotNone(run.finished_at)
        self.assertEqual(run.raw_output_path, f'scan-{self.scan.pk}/run-{run.pk}-found.json')
        saved = Path(self.results_dir.name) / run.raw_output_path
        self.assertEqual(saved.read_bytes(), b'[1, 2, 3]')

    def test_못_찾으면_이상_없음이다(self):
        run = self.make_run('passed')

        run_scan(self.scan.pk)

        run.refresh_from_db()
        self.assertEqual(run.status, ModuleRun.Status.PASSED)
        self.assertEqual(run.finding_count, 0)

    def test_도구가_실패하면_실패이고_오류_내용을_남긴다(self):
        run = self.make_run('scan_error')

        run_scan(self.scan.pk)

        run.refresh_from_db()
        self.assertEqual(run.status, ModuleRun.Status.FAILED)
        self.assertEqual(run.error_message, '저장소 폴더를 찾을 수 없습니다')
        self.assertEqual(run.raw_output_path, '')

    def test_예상하지_못한_오류도_실패로_남기고_자세한_내용은_로그에_쓴다(self):
        run = self.make_run('crash')

        with self.assertLogs('scans.tasks', 'ERROR'):
            run_scan(self.scan.pk)

        run.refresh_from_db()
        self.assertEqual(run.status, ModuleRun.Status.FAILED)
        self.assertIn('worker 로그', run.error_message)

    def test_한_칸이_실패해도_나머지_칸을_실행하고_점검을_끝낸다(self):
        failed = self.make_run('scan_error')
        found = self.make_run('found')

        run_scan(self.scan.pk)

        failed.refresh_from_db()
        found.refresh_from_db()
        self.scan.refresh_from_db()
        self.assertEqual(failed.status, ModuleRun.Status.FAILED)
        self.assertEqual(found.status, ModuleRun.Status.FOUND)
        self.assertEqual(self.scan.status, Scan.Status.DONE)
        self.assertIsNotNone(self.scan.finished_at)

    def test_실행기_자체가_멈춰도_점검은_완료로_바꿔_다음_점검을_막지_않는다(self):
        self.make_run('found')

        with patch('scans.tasks.run_module', side_effect=RuntimeError('버그')):
            with self.assertRaises(RuntimeError):
                run_scan(self.scan.pk)

        self.scan.refresh_from_db()
        self.assertEqual(self.scan.status, Scan.Status.DONE)


def fake_github_token():
    """GitHub 토큰 모양의 가짜 값. 실제 키를 코드에 두지 않으려고 실행할 때마다 새로 만든다."""
    return 'ghp_' + ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(36))


class SecretsModuleTests(TestCase):
    """컨테이너에 설치한 gitleaks를 실제로 실행한다. 저장소는 임시 폴더에 새로 만든다."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.repo = Path(self.tmp.name) / 'repo'
        self.repo.mkdir()
        self.module = SecretsModule()

    def git(self, *args):
        subprocess.run(['git', '-C', str(self.repo), *args], check=True, capture_output=True)

    def commit(self, files):
        for name, content in files.items():
            (self.repo / name).write_text(content)
        self.git('init', '-q')
        self.git('add', '.')
        self.git('-c', 'user.name=selfspar', '-c', 'user.email=selfspar@example.com', 'commit', '-q', '-m', 'test')

    def run_module(self):
        return self.module.run(Target(kind='repo', config={'path': str(self.repo)}))

    def test_커밋한_토큰을_찾고_결과에는_값을_가려서_남긴다(self):
        token = fake_github_token()
        self.commit({'settings.py': f'GITHUB_TOKEN = "{token}"\n'})

        result = self.run_module()

        self.assertEqual(len(result.findings), 1)
        self.assertNotIn(token, result.raw_output.decode())
        self.assertIn('REDACTED', result.raw_output.decode())
        self.assertRegex(result.tool_version, r'\d+\.\d+\.\d+')

    def test_찾은_결과를_발견으로_바꾸고_근거에는_값을_가린다(self):
        token = fake_github_token()
        self.commit({'settings.py': f'GITHUB_TOKEN = "{token}"\n'})

        finding = self.run_module().findings[0]

        self.assertEqual(finding.severity, 'critical')
        self.assertEqual(finding.location, 'settings.py:1')
        self.assertTrue(finding.fingerprint)
        self.assertTrue(finding.rule_id)
        self.assertIn('REDACTED', finding.evidence)
        self.assertNotIn(token, finding.evidence)
        self.assertNotIn(token, str(finding.extra))
        self.assertEqual(set(finding.extra), {'commit', 'date'})

    def test_토큰이_없으면_0개다(self):
        self.commit({'README.md': '# 안녕하세요\n'})

        self.assertEqual(self.run_module().findings, [])

    def test_커밋하지_않은_파일은_보지_않는다(self):
        self.commit({'README.md': '# 안녕하세요\n'})
        (self.repo / '.env').write_text(f'GITHUB_TOKEN={fake_github_token()}\n')

        self.assertEqual(self.run_module().findings, [])

    def test_값이_가려지지_않은_결과는_저장하지_않고_실패한다(self):
        leak = {
            'RuleID': 'github-pat', 'Description': 'GitHub token', 'File': 'settings.py', 'StartLine': 1,
            'Match': 'GITHUB_TOKEN = "ghp_진짜값"', 'Secret': 'ghp_진짜값', 'Fingerprint': 'abc:settings.py:github-pat:1',
        }

        with self.assertRaisesMessage(ScanError, '가려지지 않은 값'):
            self.module.to_finding(leak)

    def test_긴_근거_줄은_앞부분만_남긴다(self):
        leak = {
            'RuleID': 'generic-api-key', 'File': 'a.min.js', 'StartLine': 1, 'Match': 'x' * 1000 + 'REDACTED',
            'Secret': 'REDACTED', 'Fingerprint': 'abc:a.min.js:generic-api-key:1',
        }

        finding = self.module.to_finding(leak)

        self.assertEqual(len(finding.evidence), SecretsModule.EVIDENCE_LIMIT)
        # 설명이 없으면 규칙 이름을 제목으로 쓴다.
        self.assertEqual(finding.title, 'generic-api-key')

    def test_폴더가_없으면_실패한다(self):
        with self.assertRaisesMessage(ScanError, '저장소 폴더를 찾을 수 없습니다'):
            self.module.run(Target(kind='repo', config={'path': '/no/such/repo'}))

    def test_git_저장소가_아니면_실패한다(self):
        # gitleaks만 돌리면 이 경우 '유출 없음'으로 끝난다. 점검 전에 막아야 한다.
        with self.assertRaisesMessage(ScanError, 'git 저장소로 읽지 못했습니다'):
            self.run_module()

    def test_저장소_대상에만_해당한다(self):
        self.assertTrue(self.module.applies_to(Target(kind='repo')))
        for kind in ['domain', 'api', 'apk', 'cloud']:
            with self.subTest(kind=kind):
                self.assertFalse(self.module.applies_to(Target(kind=kind)))


# 실제 trivy(0.76.2)가 lodash 4.17.20 하나만 든 package-lock.json에서 낸 결과. 설명·참고 링크 같은 긴 칸만 덜어 냈다.
TRIVY_NPM_REPORT = (Path(__file__).parent / 'testdata' / 'trivy-npm.json').read_bytes()
TRIVY_VERSION_OUTPUT = json.dumps({
    'Version': '0.76.2',
    'VulnerabilityDB': {'Version': 2, 'UpdatedAt': '2026-11-20T07:09:47.681202359Z'},
}).encode()


class DependenciesModuleTests(TestCase):
    """trivy 실행은 가짜로 바꾸고, 실제 trivy가 낸 결과 파일을 넘겨서 해석·검사만 확인한다.
    실제 trivy 실행은 맨 아래 DependenciesModuleIntegrationTests에서 따로 한다."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.repo = Path(self.tmp.name)
        # 결과 파일(fixture)과 맞춰 저장소에 잠금 파일 하나를 둔다. 잠금 파일이 없으면 trivy 전에 실패한다.
        (self.repo / 'package-lock.json').write_text('{}')
        self.module = DependenciesModule()
        self.report = TRIVY_NPM_REPORT
        self.commands = []

    def fake_run_command(self, args):
        """trivy fs는 --output 자리에 결과 파일을 쓰고, trivy version은 버전 JSON을 출력한 것처럼 꾸민다."""
        self.commands.append(args)
        if args[1] == 'fs':
            Path(args[args.index('--output') + 1]).write_bytes(self.report)
            return subprocess.CompletedProcess(args, 0, b'', b'')
        return subprocess.CompletedProcess(args, 0, TRIVY_VERSION_OUTPUT, b'')

    def run_module(self):
        with patch.object(self.module, 'run_command', side_effect=self.fake_run_command):
            return self.module.run(Target(kind='repo', config={'path': str(self.repo)}))

    def test_취약점마다_발견_하나로_바꾼다(self):
        result = self.run_module()

        self.assertEqual([f.rule_id for f in result.findings], ['CVE-2021-23337', 'CVE-2026-4800', 'CVE-2020-28500', 'CVE-2025-13465'])
        finding = result.findings[0]
        self.assertEqual(finding.fingerprint, 'package-lock.json:lodash:4.17.20:CVE-2021-23337')
        self.assertEqual(finding.title, 'nodejs-lodash: command injection via template')
        self.assertEqual(finding.severity, 'high')
        self.assertEqual(finding.location, 'package-lock.json')
        self.assertEqual(finding.evidence, 'lodash 4.17.20 → 4.17.21에서 고침')
        self.assertEqual(finding.extra, {
            'package': 'lodash', 'installed_version': '4.17.20', 'fixed_version': '4.17.21',
            'url': 'https://avd.aquasec.com/nvd/cve-2021-23337',
        })
        self.assertEqual(result.findings[2].severity, 'medium')

    def test_원본_결과와_도구_버전_DB_날짜를_남긴다(self):
        result = self.run_module()

        self.assertEqual(result.raw_output, TRIVY_NPM_REPORT)
        self.assertEqual(result.tool_version, '0.76.2 (DB 2026-11-20)')

    def test_취약점만_보고_사용_통계와_버전_확인_접속을_끈다(self):
        self.run_module()

        fs = self.commands[0]
        self.assertEqual(fs[:3], ['trivy', 'fs', str(self.repo)])
        self.assertEqual(fs[fs.index('--scanners') + 1], 'vuln')
        self.assertEqual(fs[fs.index('--cache-dir') + 1], '/data/trivy-cache')
        self.assertIn('--disable-telemetry', fs)
        self.assertIn('--skip-version-check', fs)

    def test_취약점이_없는_잠금_파일은_0개다(self):
        self.report = json.dumps({'Results': [{'Target': 'package-lock.json', 'Class': 'lang-pkgs'}]}).encode()

        self.assertEqual(self.run_module().findings, [])

    def test_의존성이_없는_잠금_파일은_trivy_결과가_비어도_0개다(self):
        # 실제 trivy는 패키지가 하나도 없는 잠금 파일을 결과에서 뺀다(0.76.2에서 확인).
        self.report = json.dumps({'SchemaVersion': 2, 'ArtifactType': 'filesystem'}).encode()

        self.assertEqual(self.run_module().findings, [])

    def test_잠금_파일이_하나도_없으면_trivy를_돌리지_않고_실패한다(self):
        # 점검할 것이 없었던 것이지 안전한 것이 아니다.
        (self.repo / 'package-lock.json').unlink()
        (self.repo / 'README.md').write_text('# 안녕하세요\n')

        with self.assertRaisesMessage(ScanError, '의존성 잠금 파일'):
            self.run_module()
        self.assertEqual(self.commands, [])

    def test_gradle_lockfile이_없는_Gradle_프로젝트가_있으면_trivy를_돌리지_않고_실패한다(self):
        (self.repo / 'build.gradle.kts').write_text('plugins { java }\n')
        (self.repo / 'api').mkdir()
        (self.repo / 'api' / 'build.gradle.kts').write_text('plugins { java }\n')

        with self.assertRaisesMessage(ScanError, '잠금 파일이 없어 의존성을 확인할 수 없는 프로젝트가 있습니다') as error:
            self.run_module()

        self.assertIn('. (build.gradle.kts), api (build.gradle.kts)', str(error.exception))
        self.assertEqual(self.commands, [])

    def test_잠금_파일이_없는_npm_Python_프로젝트도_실패한다(self):
        # 루트에 잠금 파일이 있으면 아래 폴더까지 인정되므로, 잠금 파일을 옆 폴더로 옮긴다.
        (self.repo / 'other').mkdir()
        (self.repo / 'package-lock.json').rename(self.repo / 'other' / 'package-lock.json')
        (self.repo / 'web').mkdir()
        (self.repo / 'web' / 'package.json').write_text(json.dumps({'dependencies': {'react': '^19.0.0'}}))
        (self.repo / 'ai').mkdir()
        (self.repo / 'ai' / 'pyproject.toml').write_text('[project]\nname = "ai"\ndependencies = ["fastapi"]\n')

        with self.assertRaisesMessage(ScanError, 'ai (pyproject.toml), web (package.json)'):
            self.run_module()

    def test_의존성이_없는_목록_파일과_상위_폴더의_잠금_파일은_괜찮다(self):
        # 스크립트만 있는 package.json, 도구 설정만 있는 pyproject.toml은 잠금 파일이 필요 없다.
        (self.repo / 'tools').mkdir()
        (self.repo / 'tools' / 'package.json').write_text(json.dumps({'scripts': {'lint': 'eslint .'}}))
        (self.repo / 'tools' / 'pyproject.toml').write_text('[tool.ruff]\nline-length = 120\n')
        # 모노레포는 잠금 파일이 맨 위(여기서는 저장소 루트의 package-lock.json)에 하나만 있다.
        (self.repo / 'packages' / 'ui').mkdir(parents=True)
        (self.repo / 'packages' / 'ui' / 'package.json').write_text(json.dumps({'dependencies': {'react': '^19.0.0'}}))

        self.assertEqual(len(self.run_module().findings), 4)

    def test_긴_경로는_칸_길이에_맞춰_줄인다(self):
        finding = self.module.to_finding('a/' * 300 + 'package-lock.json', {
            'VulnerabilityID': 'CVE-2021-23337', 'PkgName': 'lodash', 'InstalledVersion': '4.17.20',
        })

        self.assertRegex(finding.fingerprint, r'^sha256:[0-9a-f]{64}$')
        self.assertEqual(len(finding.location), 500)

    def test_gradle_lockfile이_있으면_점검한다(self):
        (self.repo / 'build.gradle.kts').write_text('plugins { java }\n')
        (self.repo / 'gradle.lockfile').write_text('empty=\n')

        self.assertEqual(len(self.run_module().findings), 4)

    def test_빌드_결과물_폴더의_Gradle_파일은_보지_않는다(self):
        for skipped in ['node_modules/some-lib', 'build/tmp', 'buildSrc']:
            (self.repo / skipped).mkdir(parents=True)
            (self.repo / skipped / 'build.gradle').write_text('')

        self.assertEqual(len(self.run_module().findings), 4)

    def test_고친_버전이_없으면_근거에_그렇게_적는다(self):
        finding = self.module.to_finding('uv.lock', {
            'VulnerabilityID': 'CVE-2026-0001', 'PkgName': 'requests', 'InstalledVersion': '2.0.0', 'Severity': 'UNKNOWN',
        })

        self.assertEqual(finding.evidence, 'requests 2.0.0 (아직 고친 버전 없음)')
        self.assertEqual(finding.extra['fixed_version'], '')
        # 점수가 아직 없는 취약점은 '정보'로 둔다. 제목이 없으면 취약점 번호를 쓴다.
        self.assertEqual(finding.severity, 'info')
        self.assertEqual(finding.title, 'CVE-2026-0001')

    def test_trivy가_실패하면_실패한다(self):
        def failing(args):
            return subprocess.CompletedProcess(args, 1, b'', b'FATAL failed to download vulnerability DB')

        with patch.object(self.module, 'run_command', side_effect=failing):
            with self.assertRaisesMessage(ScanError, 'failed to download vulnerability DB'):
                self.module.run(Target(kind='repo', config={'path': str(self.repo)}))

    def test_폴더가_없으면_실패한다(self):
        with self.assertRaisesMessage(ScanError, '저장소 폴더를 찾을 수 없습니다'):
            self.module.run(Target(kind='repo', config={'path': '/no/such/repo'}))

    def test_저장소_대상에만_해당한다(self):
        self.assertTrue(self.module.applies_to(Target(kind='repo')))
        for kind in ['domain', 'api', 'apk', 'cloud']:
            with self.subTest(kind=kind):
                self.assertFalse(self.module.applies_to(Target(kind=kind)))


@unittest.skipUnless(
    os.environ.get('SELFSPAR_TRIVY_INTEGRATION') == '1',
    '실제 trivy 실행은 취약점 DB를 내려받아야 해서 SELFSPAR_TRIVY_INTEGRATION=1일 때만 한다.',
)
class DependenciesModuleIntegrationTests(TestCase):
    """worker에 설치한 trivy를 실제로 실행한다. 처음에는 취약점 DB(내려받기 약 135MB, 풀면 약 1.8GB)를 받는다."""

    def test_취약한_lodash를_찾는다(self):
        with tempfile.TemporaryDirectory() as repo:
            (Path(repo) / 'package-lock.json').write_text(json.dumps({
                'name': 'sample', 'version': '1.0.0', 'lockfileVersion': 3, 'requires': True,
                'packages': {
                    '': {'name': 'sample', 'version': '1.0.0', 'dependencies': {'lodash': '4.17.20'}},
                    'node_modules/lodash': {'version': '4.17.20'},
                },
            }))

            result = DependenciesModule().run(Target(kind='repo', config={'path': repo}))

        self.assertIn('package-lock.json:lodash:4.17.20:CVE-2021-23337', [f.fingerprint for f in result.findings])
        self.assertRegex(result.tool_version, r'^\d+\.\d+\.\d+ \(DB \d{4}-\d{2}-\d{2}\)$')
