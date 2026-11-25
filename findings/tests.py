import tempfile
from pathlib import Path
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import Client, TestCase, override_settings
from django.urls import reverse

from projects.models import Project
from scans.models import ModuleRun, Scan
from scans.modules import MODULES_BY_KEY
from scans.modules.base import ModuleResult, ScanError
from scans.tasks import run_scan
from scans.tests import FakeModule, finding_data, make_target

from .models import Finding, FindingEvent


class FindingRunTestCase(TestCase):
    """가짜 모듈로 점검을 끝까지 돌려 보는 테스트의 공통 준비와 도우미"""

    def setUp(self):
        results_dir = tempfile.TemporaryDirectory()
        self.addCleanup(results_dir.cleanup)
        settings_patch = override_settings(SELFSPAR_SCAN_RESULTS_DIR=Path(results_dir.name))
        settings_patch.enable()
        self.addCleanup(settings_patch.disable)

        self.project = Project.objects.create(name='karaoke')
        self.target = make_target(self.project)

    def run_with(self, *items, module='fake'):
        """가짜 모듈이 items를 찾은 것으로 점검을 한 번 끝까지 실행하고, 그 칸을 돌려준다."""
        return self.run_fake(FakeModule(module, ModuleResult('1.0.0', b'[]', list(items))))

    def run_fake(self, fake):
        with patch.dict(MODULES_BY_KEY, {fake.key: fake}):
            scan = Scan.objects.create(project=self.project)
            run = ModuleRun.objects.create(scan=scan, target=self.target, module=fake.key)
            run_scan(scan.pk)
        run.refresh_from_db()
        return run


class FindingSaveTests(FindingRunTestCase):
    """worker가 점검 결과의 발견을 저장하는 방식"""

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

    def test_다시_나온_발견은_이번_결과로_내용을_바꾼다(self):
        # 의존성 취약점은 DB가 갱신되면 같은 취약점이라도 심각도와 고친 버전이 새로 생긴다.
        first = finding_data('fp-1')
        first.severity, first.evidence, first.extra = 'info', 'lodash 4.17.20 (아직 고친 버전 없음)', {'fixed_version': ''}
        self.run_with(first)
        again = finding_data('fp-1')
        again.severity, again.evidence, again.extra = 'high', 'lodash 4.17.20 → 4.17.21에서 고침', {'fixed_version': '4.17.21'}
        self.run_with(again)

        finding = Finding.objects.get()
        self.assertEqual(
            (finding.severity, finding.evidence, finding.extra),
            ('high', 'lodash 4.17.20 → 4.17.21에서 고침', {'fixed_version': '4.17.21'}),
        )

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


class FindingStatusTests(FindingRunTestCase):
    """점검이 끝날 때 발견 상태를 바꾸는 규칙(자동 해결·재발)"""

    def assert_status(self, fingerprint, status, module='fake'):
        self.assertEqual(Finding.objects.get(fingerprint=fingerprint, module=module).status, status)

    def events(self, fingerprint):
        return list(FindingEvent.objects.filter(finding__fingerprint=fingerprint).order_by('id'))

    def set_status(self, fingerprint, status):
        Finding.objects.filter(fingerprint=fingerprint).update(status=status)

    def test_처음_찾은_발견은_미해결이고_이력은_없다(self):
        self.run_with(finding_data('fp-1'))

        self.assert_status('fp-1', Finding.Status.OPEN)
        self.assertEqual(self.events('fp-1'), [])

    def test_다시_점검했는데_안_나온_미해결_발견은_해결됨으로_바꾸고_이력을_남긴다(self):
        self.run_with(finding_data('fp-1'), finding_data('fp-2'))
        second = self.run_with(finding_data('fp-2'))

        self.assert_status('fp-1', Finding.Status.FIXED)
        self.assert_status('fp-2', Finding.Status.OPEN)
        [event] = self.events('fp-1')
        self.assertEqual(
            (event.from_status, event.to_status, event.run, event.user, event.reason),
            (Finding.Status.OPEN, Finding.Status.FIXED, second, None, ''),
        )
        self.assertEqual(self.events('fp-2'), [])

    def test_아무것도_안_나오면_미해결_발견을_모두_해결됨으로_바꾼다(self):
        self.run_with(finding_data('fp-1'), finding_data('fp-2'))
        passed = self.run_with()

        self.assertEqual(passed.status, ModuleRun.Status.PASSED)
        self.assertEqual(set(Finding.objects.values_list('status', flat=True)), {Finding.Status.FIXED})

    def test_해결된_발견이_다시_나오면_미해결로_되돌리고_이력을_남긴다(self):
        self.run_with(finding_data('fp-1'))
        fixed_by = self.run_with()
        again = self.run_with(finding_data('fp-1'))

        self.assert_status('fp-1', Finding.Status.OPEN)
        self.assertEqual(
            [(e.from_status, e.to_status, e.run) for e in self.events('fp-1')],
            [(Finding.Status.OPEN, Finding.Status.FIXED, fixed_by), (Finding.Status.FIXED, Finding.Status.OPEN, again)],
        )

    def test_해결된_발견이_이번에도_안_나오면_그대로_두고_이력을_더하지_않는다(self):
        self.run_with(finding_data('fp-1'))
        self.run_with()
        self.run_with()

        self.assert_status('fp-1', Finding.Status.FIXED)
        self.assertEqual(len(self.events('fp-1')), 1)

    def test_오탐과_위험_수용은_나오든_안_나오든_그대로_둔다(self):
        self.run_with(finding_data('fp-1'), finding_data('fp-2'))
        self.set_status('fp-1', Finding.Status.FALSE_POSITIVE)
        self.set_status('fp-2', Finding.Status.RISK_ACCEPTED)

        self.run_with(finding_data('fp-1'))

        self.assert_status('fp-1', Finding.Status.FALSE_POSITIVE)
        self.assert_status('fp-2', Finding.Status.RISK_ACCEPTED)
        self.assertFalse(FindingEvent.objects.exists())

    def test_칸이_실패하면_상태를_바꾸지_않는다(self):
        self.run_with(finding_data('fp-1'))

        failed = self.run_fake(FakeModule('fake', error=ScanError('저장소 폴더를 찾을 수 없습니다')))

        self.assertEqual(failed.status, ModuleRun.Status.FAILED)
        self.assert_status('fp-1', Finding.Status.OPEN)
        self.assertFalse(FindingEvent.objects.exists())

    def test_도구가_도는_중에_취소된_칸은_상태를_바꾸지_않는다(self):
        self.run_with(finding_data('fp-1'))

        def cancel_scan():
            Scan.objects.get(status=Scan.Status.RUNNING).cancel()

        cancelled = self.run_fake(FakeModule('fake', ModuleResult('1.0.0', b'[]'), during_run=cancel_scan))

        self.assertEqual(cancelled.status, ModuleRun.Status.CANCELLED)
        self.assert_status('fp-1', Finding.Status.OPEN)

    def test_다른_모듈과_다른_대상의_발견은_건드리지_않는다(self):
        self.run_with(finding_data('fp-1'), module='other')
        first_target = self.target
        self.target = make_target(self.project, '다른 저장소')
        self.run_with(finding_data('fp-1'))
        self.target = first_target

        # 처음 대상의 fake 모듈만 다시 점검한다. 아무것도 안 나와도 다른 모듈·대상의 발견은 그대로다.
        self.run_with()

        self.assert_status('fp-1', Finding.Status.OPEN, module='other')
        self.assertEqual(Finding.objects.get(module='fake').status, Finding.Status.OPEN)

    def test_상태_기록이_실패하면_발견_저장과_상태_변경을_모두_되돌린다(self):
        self.run_with(finding_data('fp-1'))

        with patch('scans.tasks.FindingEvent.objects.bulk_create', side_effect=RuntimeError('DB 오류')):
            with self.assertLogs('scans.tasks', 'ERROR'):
                run = self.run_with(finding_data('fp-2'))

        self.assertEqual(run.status, ModuleRun.Status.FAILED)
        self.assert_status('fp-1', Finding.Status.OPEN)
        self.assertFalse(Finding.objects.filter(fingerprint='fp-2').exists())


class RunFindingListApiTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user('tester', password='correct-horse-battery')
        self.client.force_login(self.user)
        self.project = Project.objects.create(name='karaoke')
        self.target = make_target(self.project)

    def make_run(self):
        scan = Scan.objects.create(project=self.project, status=Scan.Status.DONE)
        return ModuleRun.objects.create(scan=scan, target=self.target, module='secrets', status=ModuleRun.Status.FOUND)

    def finding(self, fingerprint, *runs, severity=Finding.Severity.CRITICAL):
        finding = Finding.objects.create(
            target=self.target, module='secrets', fingerprint=fingerprint, rule_id='generic-api-key',
            title='Generic API Key', severity=severity, location='application.yml:16',
            evidence='api-key: REDACTED', extra={'commit': 'abc123', 'date': '2025-01-18T12:07:29Z'},
        )
        finding.runs.add(*runs)
        return finding

    def get(self, run, client=None, page=None):
        params = {'page': page} if page else {}
        return (client or self.client).get(reverse('api_run_findings', args=[run.pk]), params)

    def test_칸에서_찾은_발견만_돌려준다(self):
        run = self.make_run()
        other = self.make_run()
        self.finding('fp-1', run)
        self.finding('fp-2', other)

        response = self.get(run)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['count'], 1)
        [data] = response.json()['results']
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

        data = {item['id']: item['first_scan_id'] for item in self.get(new).json()['results']}

        continued = Finding.objects.get(fingerprint='계속')
        fresh = Finding.objects.get(fingerprint='새로')
        # 이번 점검 칸으로 걸렀어도, 이전 점검에서 본 기록까지 따져야 한다.
        self.assertEqual(data[continued.pk], old.scan_id)
        self.assertEqual(data[fresh.pk], new.scan_id)

    def test_심각한_것부터_돌려준다(self):
        run = self.make_run()
        for fingerprint, severity in [('정보', 'info'), ('보통', 'medium'), ('치명', 'critical'), ('낮음', 'low'), ('높음', 'high')]:
            self.finding(fingerprint, run, severity=severity)

        severities = [item['severity'] for item in self.get(run).json()['results']]

        # 글자 순(critical, high, info, low, medium)이 아니라 심각도 순이어야 한다.
        self.assertEqual(severities, ['critical', 'high', 'medium', 'low', 'info'])

    def test_50건씩_나눠서_돌려준다(self):
        run = self.make_run()
        for i in range(51):
            self.finding(f'fp-{i}', run)

        first = self.get(run).json()
        second = self.get(run, page=2).json()

        self.assertEqual((first['count'], len(first['results'])), (51, 50))
        self.assertIsNotNone(first['next'])
        self.assertEqual(len(second['results']), 1)
        self.assertIsNone(second['next'])
        # 두 쪽에 겹치거나 빠진 발견이 없다.
        ids = [item['id'] for item in first['results'] + second['results']]
        self.assertEqual(sorted(ids), sorted(Finding.objects.values_list('id', flat=True)))

    def test_없는_쪽은_404이다(self):
        run = self.make_run()
        self.finding('fp-1', run)

        self.assertEqual(self.get(run, page=2).status_code, 404)

    def test_없는_칸은_404이다(self):
        self.assertEqual(self.client.get(reverse('api_run_findings', args=[9999])).status_code, 404)

    def test_로그인하지_않으면_403이다(self):
        self.assertEqual(self.get(self.make_run(), client=Client()).status_code, 403)
