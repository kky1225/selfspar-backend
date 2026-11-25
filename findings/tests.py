import tempfile
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

from django.conf import settings
from django.contrib.auth import get_user_model
from django.db import IntegrityError, transaction
from django.test import Client, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from projects.models import Project
from scans.models import ModuleRun, Scan
from scans.modules import MODULES_BY_KEY
from scans.modules.base import ModuleResult, ScanError
from scans.tasks import run_scan
from scans.tests import FakeModule, finding_data, make_target

from . import tasks
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
        self.accept_risk('fp-2')

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

    def accept_risk(self, fingerprint, days=10):
        Finding.objects.filter(fingerprint=fingerprint).update(
            status=Finding.Status.RISK_ACCEPTED, accepted_until=timezone.localdate() + timedelta(days=days),
        )

    def test_위험_수용한_발견이_다시_나오며_높음_이상이_되면_미해결로_되돌린다(self):
        medium = finding_data('fp-1')
        medium.severity = 'medium'
        self.run_with(medium)
        self.accept_risk('fp-1')

        raised = finding_data('fp-1')
        raised.severity = 'high'
        again = self.run_with(raised)

        finding = Finding.objects.get(fingerprint='fp-1')
        self.assertEqual((finding.status, finding.accepted_until), (Finding.Status.OPEN, None))
        [event] = self.events('fp-1')
        self.assertEqual((event.from_status, event.to_status, event.run), (Finding.Status.RISK_ACCEPTED, Finding.Status.OPEN, again))
        self.assertIn('높음', event.reason)

    def test_위험_수용한_발견이_같은_심각도로_다시_나오면_그대로_둔다(self):
        medium = finding_data('fp-1')
        medium.severity = 'medium'
        self.run_with(medium)
        self.accept_risk('fp-1')

        self.run_with(medium)

        self.assert_status('fp-1', Finding.Status.RISK_ACCEPTED)
        self.assertEqual(self.events('fp-1'), [])

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

    def test_상태와_위험_수용_만료일을_함께_돌려준다(self):
        run = self.make_run()
        finding = self.finding('fp-1', run, severity=Finding.Severity.MEDIUM)
        until = timezone.localdate() + timedelta(days=5)
        Finding.objects.filter(pk=finding.pk).update(status=Finding.Status.RISK_ACCEPTED, accepted_until=until)

        [data] = self.get(run).json()['results']

        self.assertEqual((data['status'], data['status_label'], data['accepted_until']), ('risk_accepted', '위험 수용', until.isoformat()))


class FindingApiTestCase(TestCase):
    """발견 하나를 다루는 API 테스트의 공통 준비"""

    def setUp(self):
        self.user = get_user_model().objects.create_user('tester', password='correct-horse-battery')
        self.client.force_login(self.user)
        self.project = Project.objects.create(name='karaoke')
        self.target = make_target(self.project)
        self.today = timezone.localdate()

    def make_finding(self, severity=Finding.Severity.MEDIUM, status=Finding.Status.OPEN, accepted_until=None, fingerprint='fp-1'):
        return Finding.objects.create(
            target=self.target, module='secrets', fingerprint=fingerprint, rule_id='r', title='t', severity=severity,
            location='a:1', status=status, accepted_until=accepted_until,
        )


class FindingStatusApiTests(FindingApiTestCase):
    """사람이 발견 상태를 바꾸는 API"""

    def change(self, finding, client=None, **body):
        return (client or self.client).post(
            reverse('api_finding_status', args=[finding.pk]), body, content_type='application/json',
        )

    def days(self, n):
        return (self.today + timedelta(days=n)).isoformat()

    def test_오탐으로_바꾸면_사유와_바꾼_사람을_이력에_남긴다(self):
        finding = self.make_finding()

        response = self.change(finding, status='false_positive', reason='테스트용 가짜 키')

        self.assertEqual(response.status_code, 200)
        self.assertEqual((response.json()['status'], response.json()['status_label']), ('false_positive', '오탐'))
        finding.refresh_from_db()
        self.assertEqual((finding.status, finding.accepted_until), (Finding.Status.FALSE_POSITIVE, None))
        [event] = finding.events.all()
        self.assertEqual(
            (event.from_status, event.to_status, event.reason, event.user, event.run),
            (Finding.Status.OPEN, Finding.Status.FALSE_POSITIVE, '테스트용 가짜 키', self.user, None),
        )

    def test_보통은_30일까지_위험_수용할_수_있다(self):
        finding = self.make_finding()

        response = self.change(finding, status='risk_accepted', reason='관리자 화면에서만 씀', accepted_until=self.days(30))

        self.assertEqual(response.status_code, 200)
        finding.refresh_from_db()
        self.assertEqual((finding.status, finding.accepted_until.isoformat()), (Finding.Status.RISK_ACCEPTED, self.days(30)))
        self.assertEqual(finding.events.get().accepted_until.isoformat(), self.days(30))

    def test_보통을_31일_넘게_위험_수용하면_400이다(self):
        response = self.change(self.make_finding(), status='risk_accepted', reason='사유', accepted_until=self.days(31))

        self.assertEqual(response.status_code, 400)
        self.assertIn('30일', response.json()['accepted_until'][0])

    def test_낮음과_정보는_90일까지_위험_수용할_수_있다(self):
        for n, severity in enumerate([Finding.Severity.LOW, Finding.Severity.INFO]):
            with self.subTest(severity=severity):
                finding = self.make_finding(severity=severity, fingerprint=f'fp-{n}')
                ok = self.change(finding, status='risk_accepted', reason='사유', accepted_until=self.days(90))
                self.assertEqual(ok.status_code, 200)

        too_long = self.make_finding(severity=Finding.Severity.LOW, fingerprint='fp-long')
        self.assertEqual(self.change(too_long, status='risk_accepted', reason='사유', accepted_until=self.days(91)).status_code, 400)

    def test_치명과_높음은_위험_수용할_수_없다(self):
        for n, severity in enumerate([Finding.Severity.CRITICAL, Finding.Severity.HIGH]):
            with self.subTest(severity=severity):
                finding = self.make_finding(severity=severity, fingerprint=f'fp-{n}')
                response = self.change(finding, status='risk_accepted', reason='사유', accepted_until=self.days(1))
                self.assertEqual(response.status_code, 400)
                self.assertIn('status', response.json())
        self.assertFalse(FindingEvent.objects.exists())

    def test_위험_수용_만료일은_내일_이후여야_하고_반드시_있어야_한다(self):
        finding = self.make_finding()

        for body in [{'accepted_until': self.days(0)}, {'accepted_until': self.days(-1)}, {}, {'accepted_until': None}]:
            with self.subTest(body=body):
                response = self.change(finding, status='risk_accepted', reason='사유', **body)
                self.assertEqual(response.status_code, 400)
                self.assertIn('accepted_until', response.json())
        self.assertEqual(self.change(finding, status='risk_accepted', reason='사유', accepted_until=self.days(1)).status_code, 200)

    def test_위험_수용_기한을_연장할_수_있고_이력이_남는다(self):
        finding = self.make_finding(status=Finding.Status.RISK_ACCEPTED, accepted_until=self.today + timedelta(days=3))

        response = self.change(finding, status='risk_accepted', reason='아직 고칠 버전이 없음', accepted_until=self.days(20))

        self.assertEqual(response.status_code, 200)
        finding.refresh_from_db()
        self.assertEqual(finding.accepted_until.isoformat(), self.days(20))
        event = finding.events.get()
        self.assertEqual((event.from_status, event.to_status), (Finding.Status.RISK_ACCEPTED, Finding.Status.RISK_ACCEPTED))

    def test_같은_만료일로_다시_위험_수용하면_400이다(self):
        finding = self.make_finding(status=Finding.Status.RISK_ACCEPTED, accepted_until=self.today + timedelta(days=3))

        response = self.change(finding, status='risk_accepted', reason='사유', accepted_until=self.days(3))

        self.assertEqual(response.status_code, 400)
        self.assertFalse(FindingEvent.objects.exists())

    def test_미해결로_되돌리면_만료일을_비운다(self):
        finding = self.make_finding(status=Finding.Status.RISK_ACCEPTED, accepted_until=self.today + timedelta(days=3))

        response = self.change(finding, status='open', reason='공개 화면에서도 쓰게 됨')

        self.assertEqual(response.status_code, 200)
        finding.refresh_from_db()
        self.assertEqual((finding.status, finding.accepted_until), (Finding.Status.OPEN, None))

    def test_위험_수용이_아닌데_만료일을_보내면_400이다(self):
        response = self.change(self.make_finding(), status='false_positive', reason='사유', accepted_until=self.days(3))

        self.assertEqual(response.status_code, 400)
        self.assertIn('accepted_until', response.json())

    def test_같은_상태로_바꾸면_400이다(self):
        self.assertEqual(self.change(self.make_finding(), status='open', reason='사유').status_code, 400)

    def test_해결됨은_고를_수_없다(self):
        response = self.change(self.make_finding(), status='fixed', reason='고쳤음')

        self.assertEqual(response.status_code, 400)
        self.assertIn('다시 점검', response.json()['status'][0])

    def test_해결된_발견은_바꿀_수_없다(self):
        finding = self.make_finding(status=Finding.Status.FIXED)

        response = self.change(finding, status='false_positive', reason='사유')

        self.assertEqual(response.status_code, 409)
        finding.refresh_from_db()
        self.assertEqual(finding.status, Finding.Status.FIXED)

    def test_사유는_반드시_1자에서_280자로_적는다(self):
        finding = self.make_finding()

        for reason in [None, '', '   ', '가' * 281]:
            with self.subTest(reason=reason):
                body = {} if reason is None else {'reason': reason}
                response = self.change(finding, status='false_positive', **body)
                self.assertEqual(response.status_code, 400)
                self.assertIn('reason', response.json())
        self.assertEqual(self.change(finding, status='false_positive', reason='가' * 280).status_code, 200)

    def test_상태와_만료일만_저장하고_다른_칸은_덮어쓰지_않는다(self):
        finding = self.make_finding()
        real_create = FindingEvent.objects.create

        # view가 발견을 읽은 뒤, 저장하기 전에 DB의 제목이 바뀐 상황을 만든다(이력을 남기는 순간에 바꾼다).
        # view가 발견을 통째로 저장하면 읽어 둔 옛 제목('t')으로 덮어써서 이 테스트가 실패한다.
        def title_changes_before_save(**kwargs):
            Finding.objects.filter(pk=finding.pk).update(title='점검이 바꾼 제목')
            return real_create(**kwargs)

        with patch.object(FindingEvent.objects, 'create', title_changes_before_save):
            self.assertEqual(self.change(finding, status='false_positive', reason='사유').status_code, 200)

        finding.refresh_from_db()
        self.assertEqual((finding.status, finding.title), (Finding.Status.FALSE_POSITIVE, '점검이 바꾼 제목'))

    def test_없는_발견은_404이다(self):
        response = self.client.post(
            reverse('api_finding_status', args=[9999]), {'status': 'open', 'reason': '사유'}, content_type='application/json',
        )
        self.assertEqual(response.status_code, 404)

    def test_로그인하지_않으면_403이다(self):
        response = self.change(self.make_finding(), client=Client(), status='false_positive', reason='사유')

        self.assertEqual(response.status_code, 403)
        self.assertFalse(FindingEvent.objects.exists())


class FindingEventListApiTests(FindingApiTestCase):
    """발견 상태 이력 조회 API"""

    def test_최근_것부터_돌려주고_바꾼_사람이나_점검을_알려_준다(self):
        finding = self.make_finding(status=Finding.Status.FALSE_POSITIVE)
        scan = Scan.objects.create(project=self.project, status=Scan.Status.DONE)
        run = ModuleRun.objects.create(scan=scan, target=self.target, module='secrets')
        by_scan = FindingEvent.objects.create(finding=finding, from_status='open', to_status='fixed', run=run)
        by_user = FindingEvent.objects.create(
            finding=finding, from_status='fixed', to_status='false_positive', reason='테스트 키', user=self.user,
        )

        response = self.client.get(reverse('api_finding_events', args=[finding.pk]))

        self.assertEqual(response.status_code, 200)
        first, second = response.json()
        self.assertEqual(
            (first['id'], first['to_status_label'], first['reason'], first['username'], first['scan_id']),
            (by_user.pk, '오탐', '테스트 키', 'tester', None),
        )
        self.assertEqual(
            (second['id'], second['from_status_label'], second['to_status_label'], second['username'], second['scan_id']),
            (by_scan.pk, '미해결', '해결됨', None, scan.pk),
        )

    def test_다른_발견의_이력은_섞지_않는다(self):
        finding = self.make_finding()
        other = self.make_finding(fingerprint='fp-2')
        FindingEvent.objects.create(finding=other, from_status='open', to_status='fixed')

        self.assertEqual(self.client.get(reverse('api_finding_events', args=[finding.pk])).json(), [])

    def test_없는_발견은_404이고_로그인하지_않으면_403이다(self):
        self.assertEqual(self.client.get(reverse('api_finding_events', args=[9999])).status_code, 404)
        finding = self.make_finding()
        self.assertEqual(Client().get(reverse('api_finding_events', args=[finding.pk])).status_code, 403)


class ExpireRiskAcceptancesTests(FindingApiTestCase):
    """기한이 지난 위험 수용을 미해결로 되돌리는 작업"""

    def test_만료일이_지난_위험_수용은_미해결로_되돌리고_이력을_남긴다(self):
        expired = self.make_finding(status=Finding.Status.RISK_ACCEPTED, accepted_until=self.today - timedelta(days=1))

        with self.assertLogs('findings.tasks', 'INFO'):
            tasks.expire_risk_acceptances()

        expired.refresh_from_db()
        self.assertEqual((expired.status, expired.accepted_until), (Finding.Status.OPEN, None))
        [event] = expired.events.all()
        self.assertEqual(
            (event.from_status, event.to_status, event.reason, event.user, event.run),
            (Finding.Status.RISK_ACCEPTED, Finding.Status.OPEN, tasks.EXPIRED_REASON, None, None),
        )

    def test_만료일_당일과_그_뒤는_그대로_둔다(self):
        today = self.make_finding(status=Finding.Status.RISK_ACCEPTED, accepted_until=self.today)
        later = self.make_finding(status=Finding.Status.RISK_ACCEPTED, accepted_until=self.today + timedelta(days=1), fingerprint='fp-2')

        tasks.expire_risk_acceptances()

        for finding in (today, later):
            finding.refresh_from_db()
            self.assertEqual(finding.status, Finding.Status.RISK_ACCEPTED)
        self.assertFalse(FindingEvent.objects.exists())

    def test_다른_상태는_건드리지_않는다(self):
        for n, status in enumerate([Finding.Status.OPEN, Finding.Status.FIXED, Finding.Status.FALSE_POSITIVE]):
            self.make_finding(status=status, fingerprint=f'fp-{n}')

        tasks.expire_risk_acceptances()

        self.assertEqual(
            sorted(Finding.objects.values_list('status', flat=True)),
            sorted([Finding.Status.OPEN, Finding.Status.FIXED, Finding.Status.FALSE_POSITIVE]),
        )
        self.assertFalse(FindingEvent.objects.exists())

    def test_1시간마다_실행하도록_등록되어_있다(self):
        entry = settings.CELERY_BEAT_SCHEDULE['expire-risk-acceptances']
        self.assertEqual(entry['task'], tasks.expire_risk_acceptances.name)
        self.assertEqual(entry['schedule'], 60 * 60.0)
        self.assertEqual(entry['options']['expires'], 60 * 60)


class AcceptedUntilConstraintTests(FindingApiTestCase):
    """위험 수용일 때만 만료일이 있도록 DB가 막는다"""

    def test_위험_수용인데_만료일이_없으면_저장되지_않는다(self):
        with self.assertRaises(IntegrityError), transaction.atomic():
            self.make_finding(status=Finding.Status.RISK_ACCEPTED, accepted_until=None)

    def test_위험_수용이_아닌데_만료일이_있으면_저장되지_않는다(self):
        with self.assertRaises(IntegrityError), transaction.atomic():
            self.make_finding(status=Finding.Status.OPEN, accepted_until=self.today)
