import secrets
import string
import subprocess
import tempfile
from pathlib import Path
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.db import IntegrityError
from django.test import Client, TestCase, override_settings
from django.urls import reverse

from projects.models import Project, Target

from .models import Scan, ScanTask
from .modules import MODULES_BY_KEY
from .modules.base import ModuleResult, ScanError, ScanModule
from .modules.secrets import SecretsModule
from .tasks import run_scan


def make_target(project, name='로컬', kind='repo', path='/repo'):
    config = {'path': path} if kind == 'repo' else {'base_url': 'http://localhost:8081', 'token_location': 'header'}
    return Target.objects.create(project=project, name=name, kind=kind, environment='local', config=config)


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
        # 저장소 대상 × 시크릿 모듈 한 칸만 생긴다. API 대상에는 아직 해당하는 모듈이 없다.
        self.assertEqual(list(scan.tasks.values_list('target', 'module')), [(self.repo.pk, 'secrets')])
        data = response.json()
        self.assertEqual(data['id'], scan.pk)
        self.assertEqual(data['status_label'], '대기')
        self.assertEqual(data['modules'], [{'key': 'secrets', 'label': '시크릿 유출'}])

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
        self.assertFalse(ScanTask.objects.exists())

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
    def test_최근_점검부터_칸_상태별_개수와_함께_돌려준다(self):
        old = Scan.objects.create(project=self.project, status=Scan.Status.DONE)
        ScanTask.objects.create(scan=old, target=self.repo, module='secrets', status=ScanTask.Status.FOUND)
        ScanTask.objects.create(scan=old, target=self.api, module='other', status=ScanTask.Status.FAILED)
        new = Scan.objects.create(project=self.project)
        ScanTask.objects.create(scan=new, target=self.repo, module='secrets', status=ScanTask.Status.PASSED)
        ScanTask.objects.create(scan=new, target=self.api, module='other', status=ScanTask.Status.RUNNING)

        response = self.client.get(reverse('api_scan_list', args=[self.project.pk]))

        self.assertEqual(response.status_code, 200)
        first, second = response.json()
        self.assertEqual(first['id'], new.pk)
        self.assertEqual(
            (first['task_count'], first['finished_task_count'], first['found_count'], first['failed_count']),
            (2, 1, 0, 0),
        )
        self.assertEqual(second['id'], old.pk)
        self.assertEqual(
            (second['task_count'], second['finished_task_count'], second['found_count'], second['failed_count']),
            (2, 2, 1, 1),
        )

    def test_다른_프로젝트의_점검은_보이지_않는다(self):
        other = Project.objects.create(name='investfeed')
        Scan.objects.create(project=other)

        response = self.client.get(reverse('api_scan_list', args=[self.project.pk]))

        self.assertEqual(response.json(), [])


class ScanDetailApiTests(ScanApiTestCase):
    def test_격자에_필요한_모듈_대상_칸을_돌려준다(self):
        scan = Scan.objects.create(project=self.project)
        ScanTask.objects.create(
            scan=scan, target=self.repo, module='secrets', status=ScanTask.Status.FOUND,
            finding_count=2, tool_version='8.30.1', raw_output_path='scan-1/task-1-secrets.json',
        )

        response = self.client.get(reverse('api_scan_detail', args=[scan.pk]))

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data['project'], {'id': self.project.pk, 'name': 'karaoke'})
        self.assertEqual([target['name'] for target in data['targets']], ['로컬', '관리자'])
        self.assertEqual(data['targets'][0]['kind_label'], '저장소')
        task = data['tasks'][0]
        self.assertEqual(task['target'], self.repo.pk)
        self.assertEqual(task['status_label'], '발견')
        self.assertEqual(task['finding_count'], 2)
        # 서버 안의 파일 경로는 화면에 보낼 필요가 없다.
        self.assertNotIn('raw_output_path', task)

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
            'found': FakeModule('found', ModuleResult(3, '1.0.0', b'[1, 2, 3]')),
            'passed': FakeModule('passed', ModuleResult(0, '1.0.0', b'[]')),
            'scan_error': FakeModule('scan_error', error=ScanError('저장소 폴더를 찾을 수 없습니다')),
            'crash': FakeModule('crash', error=KeyError('path')),
        }
        modules_patch = patch.dict(MODULES_BY_KEY, fakes)
        modules_patch.start()
        self.addCleanup(modules_patch.stop)

        project = Project.objects.create(name='karaoke')
        self.target = make_target(project)
        self.scan = Scan.objects.create(project=project)

    def task(self, module):
        return ScanTask.objects.create(scan=self.scan, target=self.target, module=module)

    def test_찾으면_발견이고_원본_결과를_파일로_보관한다(self):
        task = self.task('found')

        run_scan(self.scan.pk)

        task.refresh_from_db()
        self.assertEqual(task.status, ScanTask.Status.FOUND)
        self.assertEqual(task.finding_count, 3)
        self.assertEqual(task.tool_version, '1.0.0')
        self.assertIsNotNone(task.started_at)
        self.assertIsNotNone(task.finished_at)
        self.assertEqual(task.raw_output_path, f'scan-{self.scan.pk}/task-{task.pk}-found.json')
        saved = Path(self.results_dir.name) / task.raw_output_path
        self.assertEqual(saved.read_bytes(), b'[1, 2, 3]')

    def test_못_찾으면_이상_없음이다(self):
        task = self.task('passed')

        run_scan(self.scan.pk)

        task.refresh_from_db()
        self.assertEqual(task.status, ScanTask.Status.PASSED)
        self.assertEqual(task.finding_count, 0)

    def test_도구가_실패하면_실패이고_오류_내용을_남긴다(self):
        task = self.task('scan_error')

        run_scan(self.scan.pk)

        task.refresh_from_db()
        self.assertEqual(task.status, ScanTask.Status.FAILED)
        self.assertEqual(task.error_message, '저장소 폴더를 찾을 수 없습니다')
        self.assertEqual(task.raw_output_path, '')

    def test_예상하지_못한_오류도_실패로_남기고_자세한_내용은_로그에_쓴다(self):
        task = self.task('crash')

        with self.assertLogs('scans.tasks', 'ERROR'):
            run_scan(self.scan.pk)

        task.refresh_from_db()
        self.assertEqual(task.status, ScanTask.Status.FAILED)
        self.assertIn('worker 로그', task.error_message)

    def test_한_칸이_실패해도_나머지_칸을_실행하고_점검을_끝낸다(self):
        failed = self.task('scan_error')
        found = self.task('found')

        run_scan(self.scan.pk)

        failed.refresh_from_db()
        found.refresh_from_db()
        self.scan.refresh_from_db()
        self.assertEqual(failed.status, ScanTask.Status.FAILED)
        self.assertEqual(found.status, ScanTask.Status.FOUND)
        self.assertEqual(self.scan.status, Scan.Status.DONE)
        self.assertIsNotNone(self.scan.finished_at)

    def test_실행기_자체가_멈춰도_점검은_완료로_바꿔_다음_점검을_막지_않는다(self):
        self.task('found')

        with patch('scans.tasks.run_task', side_effect=RuntimeError('버그')):
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

        self.assertEqual(result.finding_count, 1)
        self.assertNotIn(token, result.raw_output.decode())
        self.assertIn('REDACTED', result.raw_output.decode())
        self.assertRegex(result.tool_version, r'\d+\.\d+\.\d+')

    def test_토큰이_없으면_0개다(self):
        self.commit({'README.md': '# 안녕하세요\n'})

        self.assertEqual(self.run_module().finding_count, 0)

    def test_커밋하지_않은_파일은_보지_않는다(self):
        self.commit({'README.md': '# 안녕하세요\n'})
        (self.repo / '.env').write_text(f'GITHUB_TOKEN={fake_github_token()}\n')

        self.assertEqual(self.run_module().finding_count, 0)

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
