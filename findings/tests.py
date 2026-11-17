import tempfile
from pathlib import Path
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import Client, TestCase, override_settings
from django.urls import reverse

from projects.models import Project
from scans.models import ModuleRun, Scan
from scans.modules import MODULES_BY_KEY
from scans.modules.base import ModuleResult
from scans.tasks import run_scan
from scans.tests import FakeModule, finding_data, make_target

from .models import Finding


class FindingSaveTests(TestCase):
    """worker가 점검 결과의 발견을 저장하는 방식"""

    def setUp(self):
        results_dir = tempfile.TemporaryDirectory()
        self.addCleanup(results_dir.cleanup)
        settings_patch = override_settings(SELFSPAR_SCAN_RESULTS_DIR=Path(results_dir.name))
        settings_patch.enable()
        self.addCleanup(settings_patch.disable)

        self.project = Project.objects.create(name='karaoke')
        self.target = make_target(self.project)

    def run_with(self, *items):
        """가짜 모듈이 items를 찾은 것으로 점검을 한 번 끝까지 실행하고, 그 칸을 돌려준다."""
        fake = FakeModule('fake', ModuleResult('1.0.0', b'[]', list(items)))
        with patch.dict(MODULES_BY_KEY, {'fake': fake}):
            scan = Scan.objects.create(project=self.project)
            run = ModuleRun.objects.create(scan=scan, target=self.target, module='fake')
            run_scan(scan.pk)
        run.refresh_from_db()
        return run

    def test_찾은_발견을_저장하고_칸에_잇는다(self):
        run = self.run_with(finding_data('fp-1', 'settings.py:3'), finding_data('fp-2'))

        self.assertEqual(run.status, ModuleRun.Status.FOUND)
        self.assertEqual(run.finding_count, 2)
        finding = Finding.objects.get(fingerprint='fp-1')
        self.assertEqual(
            (finding.target, finding.module, finding.rule_id, finding.severity, finding.location),
            (self.target, 'fake', 'generic-api-key', 'critical', 'settings.py:3'),
        )
        self.assertEqual(finding.extra, {'commit': 'abc123'})
        self.assertEqual(set(run.findings.values_list('fingerprint', flat=True)), {'fp-1', 'fp-2'})

    def test_다음_점검에서_같은_발견이_나오면_새로_만들지_않고_다시_잇는다(self):
        first = self.run_with(finding_data('fp-1'))
        second = self.run_with(finding_data('fp-1'), finding_data('fp-2'))

        self.assertEqual(Finding.objects.count(), 2)
        same = Finding.objects.get(fingerprint='fp-1')
        self.assertEqual(set(same.runs.all()), {first, second})
        self.assertEqual(second.finding_count, 2)

    def test_한_결과_안에서_겹친_발견은_하나로_센다(self):
        run = self.run_with(finding_data('fp-1'), finding_data('fp-1'))

        self.assertEqual(run.finding_count, 1)
        self.assertEqual(Finding.objects.count(), 1)

    def test_대상이_다르면_fingerprint가_같아도_다른_발견이다(self):
        self.run_with(finding_data('fp-1'))
        self.target = make_target(self.project, '다른 저장소')
        self.run_with(finding_data('fp-1'))

        self.assertEqual(Finding.objects.count(), 2)

    def test_발견_저장이_실패하면_칸은_실패이고_발견은_남지_않는다(self):
        with patch('scans.tasks.Finding.objects.bulk_create', side_effect=RuntimeError('DB 오류')):
            with self.assertLogs('scans.tasks', 'ERROR'):
                run = self.run_with(finding_data('fp-1'))

        self.assertEqual(run.status, ModuleRun.Status.FAILED)
        self.assertEqual(run.finding_count, 0)
        self.assertFalse(Finding.objects.exists())


class RunFindingListApiTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user('tester', password='correct-horse-battery')
        self.client.force_login(self.user)
        self.project = Project.objects.create(name='karaoke')
        self.target = make_target(self.project)

    def make_run(self):
        scan = Scan.objects.create(project=self.project, status=Scan.Status.DONE)
        return ModuleRun.objects.create(scan=scan, target=self.target, module='secrets', status=ModuleRun.Status.FOUND)

    def finding(self, fingerprint, *runs):
        finding = Finding.objects.create(
            target=self.target, module='secrets', fingerprint=fingerprint, rule_id='generic-api-key',
            title='Generic API Key', severity=Finding.Severity.CRITICAL, location='application.yml:16',
            evidence='api-key: REDACTED', extra={'commit': 'abc123', 'date': '2025-01-18T12:07:29Z'},
        )
        finding.runs.add(*runs)
        return finding

    def get(self, run, client=None):
        return (client or self.client).get(reverse('api_run_findings', args=[run.pk]))

    def test_칸에서_찾은_발견만_돌려준다(self):
        run = self.make_run()
        other = self.make_run()
        self.finding('fp-1', run)
        self.finding('fp-2', other)

        response = self.get(run)

        self.assertEqual(response.status_code, 200)
        [data] = response.json()
        self.assertEqual(data['rule_id'], 'generic-api-key')
        self.assertEqual(data['severity_label'], '치명')
        self.assertEqual(data['location'], 'application.yml:16')
        self.assertEqual(data['evidence'], 'api-key: REDACTED')
        self.assertEqual(data['extra']['commit'], 'abc123')

    def test_처음_본_점검_번호를_알려_준다(self):
        old = self.make_run()
        new = self.make_run()
        self.finding('계속', old, new)
        self.finding('새로', new)

        data = {item['id']: item['first_scan_id'] for item in self.get(new).json()}

        continued = Finding.objects.get(fingerprint='계속')
        fresh = Finding.objects.get(fingerprint='새로')
        # 이번 점검 칸으로 걸렀어도, 이전 점검에서 본 기록까지 따져야 한다.
        self.assertEqual(data[continued.pk], old.scan_id)
        self.assertEqual(data[fresh.pk], new.scan_id)

    def test_없는_칸은_404이다(self):
        self.assertEqual(self.client.get(reverse('api_run_findings', args=[9999])).status_code, 404)

    def test_로그인하지_않으면_403이다(self):
        self.assertEqual(self.get(self.make_run(), client=Client()).status_code, 403)
