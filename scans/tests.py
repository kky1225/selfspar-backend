import json
import os
import secrets
import string
import subprocess
import sys
import time
import unittest
import tempfile
from contextlib import contextmanager
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from django.conf import settings
from django.contrib.auth import get_user_model
from django.db import DatabaseError, IntegrityError, transaction
from django.test import Client, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from projects.models import Project, Target

from .models import ModuleRun, Scan
from .modules import MODULES_BY_KEY
from .modules.base import Cancelled, FindingData, ModuleResult, ScanError, ScanModule, never_cancelled
from .modules.dependencies import DependenciesModule
from .modules.secrets import SecretsModule
from . import tasks
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

    def start(self, project=None, client=None, data=None):
        url = reverse('api_scan_list', args=[(project or self.project).pk])
        return (client or self.client).post(url, data, content_type='application/json')


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
        self.assertIsNone(data['source_scan'])
        self.assertEqual(
            data['modules'],
            [
                {'key': 'secrets', 'label': '시크릿 유출', 'kinds': ['repo']},
                {'key': 'dependencies', 'label': '의존성 취약점', 'kinds': ['repo']},
            ],
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


class ScanRescanApiTests(ScanApiTestCase):
    def setUp(self):
        super().setUp()
        # 끝난 지난 점검. 저장소 대상의 시크릿 칸은 발견, 의존성 칸은 실패였다.
        self.source = Scan.objects.create(project=self.project, status=Scan.Status.DONE)
        self.secrets_run = ModuleRun.objects.create(
            scan=self.source, target=self.repo, module='secrets', status=ModuleRun.Status.FOUND, finding_count=2,
        )
        self.deps_run = ModuleRun.objects.create(
            scan=self.source, target=self.repo, module='dependencies', status=ModuleRun.Status.FAILED,
        )

    def rescan(self, run_ids, source=None):
        return self.start(data={'source_scan': (source or self.source).pk, 'run_ids': run_ids})

    def test_고른_칸만_새_점검으로_다시_돌린다(self):
        response = self.rescan([self.deps_run.pk])

        self.assertEqual(response.status_code, 201)
        scan = Scan.objects.get(pk=response.json()['id'])
        self.assertEqual(scan.source_scan, self.source)
        self.assertEqual(response.json()['source_scan'], self.source.pk)
        self.assertEqual(list(scan.runs.values_list('target', 'module', 'status')), [(self.repo.pk, 'dependencies', 'queued')])
        self.run_scan.delay.assert_called_once_with(scan.pk)

    def test_지난_점검의_칸은_그대로_둔다(self):
        self.rescan([self.secrets_run.pk, self.deps_run.pk])

        self.secrets_run.refresh_from_db()
        self.assertEqual((self.secrets_run.scan, self.secrets_run.status), (self.source, ModuleRun.Status.FOUND))
        self.assertEqual(self.source.runs.count(), 2)

    def test_같은_칸을_여러_번_보내도_한_번만_돌린다(self):
        response = self.rescan([self.deps_run.pk, self.deps_run.pk])

        self.assertEqual(response.status_code, 201)
        self.assertEqual(Scan.objects.get(pk=response.json()['id']).runs.count(), 1)

    def test_재점검을_다시_점검할_수_있다(self):
        first = Scan.objects.get(pk=self.rescan([self.deps_run.pk]).json()['id'])
        first.status = Scan.Status.DONE
        first.save()

        response = self.rescan([first.runs.get().pk], source=first)

        self.assertEqual(response.status_code, 201)
        self.assertEqual(Scan.objects.get(pk=response.json()['id']).source_scan, first)

    def assert_rejected(self, response, field):
        self.assertEqual(response.status_code, 400)
        self.assertIn(field, response.json())
        # 지난 점검 하나만 남아 있어야 한다.
        self.assertEqual(Scan.objects.count(), 1)
        self.run_scan.delay.assert_not_called()

    def test_칸을_하나도_고르지_않으면_400이다(self):
        self.assert_rejected(self.rescan([]), 'run_ids')

    def test_다른_점검의_칸이_섞이면_400이다(self):
        other = Scan.objects.create(project=self.project, status=Scan.Status.DONE)
        other_run = ModuleRun.objects.create(scan=other, target=self.repo, module='secrets')

        response = self.rescan([self.deps_run.pk, other_run.pk])

        self.assertEqual(response.status_code, 400)
        self.assertIn('run_ids', response.json())
        self.assertEqual(Scan.objects.count(), 2)

    def test_다른_프로젝트의_점검은_400이다(self):
        other_project = Project.objects.create(name='investfeed')
        other = Scan.objects.create(project=other_project, status=Scan.Status.DONE)

        self.assertEqual(self.rescan([self.deps_run.pk], source=other).status_code, 400)
        self.assertFalse(Scan.objects.filter(source_scan__isnull=False).exists())

    def test_없는_점검은_400이다(self):
        self.assert_rejected(self.start(data={'source_scan': 9999, 'run_ids': [self.deps_run.pk]}), 'source_scan')

    def test_지금은_없는_모듈의_칸은_400이다(self):
        removed = ModuleRun.objects.create(scan=self.source, target=self.repo, module='removed')

        self.assert_rejected(self.rescan([removed.pk]), 'run_ids')

    def test_대상_종류가_바뀌어_해당하지_않는_칸은_400이다(self):
        self.repo.kind = Target.Kind.API
        self.repo.save()

        self.assert_rejected(self.rescan([self.deps_run.pk]), 'run_ids')

    def test_실행_중인_점검이_있으면_409이다(self):
        Scan.objects.create(project=self.project, status=Scan.Status.RUNNING)

        self.assertEqual(self.rescan([self.deps_run.pk]).status_code, 409)
        self.assertFalse(Scan.objects.filter(source_scan__isnull=False).exists())

    def test_지난_점검을_지우면_재점검도_함께_지운다(self):
        scan_id = self.rescan([self.deps_run.pk]).json()['id']

        self.source.delete()

        self.assertFalse(Scan.objects.filter(pk=scan_id).exists())
        self.assertFalse(ModuleRun.objects.filter(scan_id=scan_id).exists())


class ScanCancelApiTests(ScanApiTestCase):
    def cancel(self, scan, client=None):
        return (client or self.client).post(reverse('api_scan_cancel', args=[scan.pk]), content_type='application/json')

    def make_scan(self, status=Scan.Status.RUNNING):
        scan = Scan.objects.create(project=self.project, status=status)
        self.done_run = ModuleRun.objects.create(
            scan=scan, target=self.repo, module='secrets', status=ModuleRun.Status.FOUND, finding_count=2,
        )
        self.running_run = ModuleRun.objects.create(
            scan=scan, target=self.repo, module='dependencies', status=ModuleRun.Status.RUNNING,
        )
        self.queued_run = ModuleRun.objects.create(scan=scan, target=self.api, module='other')
        return scan

    def test_실행_중인_점검을_취소하면_끝나지_않은_칸만_취소로_바꾼다(self):
        scan = self.make_scan()

        response = self.cancel(scan)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['status_label'], '취소')
        scan.refresh_from_db()
        self.assertEqual(scan.status, Scan.Status.CANCELLED)
        self.assertIsNotNone(scan.finished_at)
        statuses = dict(scan.runs.values_list('pk', 'status'))
        self.assertEqual(statuses, {
            self.done_run.pk: ModuleRun.Status.FOUND,
            self.running_run.pk: ModuleRun.Status.CANCELLED,
            self.queued_run.pk: ModuleRun.Status.CANCELLED,
        })

    def test_대기_중인_점검도_취소할_수_있다(self):
        self.assertEqual(self.cancel(self.make_scan(Scan.Status.QUEUED)).status_code, 200)

    def test_취소하면_바로_새_점검을_시작할_수_있다(self):
        self.cancel(self.make_scan())

        self.assertEqual(self.start().status_code, 201)

    def test_끝난_점검은_409이고_그대로_둔다(self):
        for finished in [Scan.Status.DONE, Scan.Status.CANCELLED]:
            with self.subTest(status=finished):
                scan = Scan.objects.create(project=self.project, status=finished)
                run = ModuleRun.objects.create(scan=scan, target=self.repo, module='secrets', status=ModuleRun.Status.FAILED)

                response = self.cancel(scan)

                self.assertEqual(response.status_code, 409)
                scan.refresh_from_db()
                run.refresh_from_db()
                self.assertEqual((scan.status, run.status), (finished, ModuleRun.Status.FAILED))

    def test_없는_점검은_404이다(self):
        response = self.client.post(reverse('api_scan_cancel', args=[9999]))

        self.assertEqual(response.status_code, 404)

    def test_로그인하지_않으면_403이다(self):
        scan = self.make_scan()

        self.assertEqual(self.cancel(scan, client=Client()).status_code, 403)
        scan.refresh_from_db()
        self.assertEqual(scan.status, Scan.Status.RUNNING)

    def test_CSRF_토큰_없이는_취소할_수_없다(self):
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.user)
        scan = self.make_scan()

        self.assertEqual(self.cancel(scan, client=client).status_code, 403)


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

    def __init__(self, key, result=None, error=None, during_run=None):
        self.key = key
        self.result = result
        self.error = error
        # 도구가 도는 도중에 일어나는 일(예: 점검 취소)을 흉내 낸다.
        self.during_run = during_run

    def run(self, target, cancelled):
        if self.during_run:
            self.during_run()
        if self.error:
            raise self.error
        return self.result


class CheckingModule(ScanModule):
    """도는 도중에 취소 확인 함수를 불러 보고, 돌려받은 답을 남기는 가짜 모듈"""

    key = 'checking'
    kinds = (Target.Kind.REPO,)

    def __init__(self, before_check):
        self.before_check = before_check
        self.answers = []

    def run(self, target, cancelled):
        self.before_check()
        self.answers.append(cancelled())
        return ModuleResult('1.0.0', b'[]')


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

    def test_칸을_끝내다_오류가_나도_그_칸만_실패로_두고_다음_칸으로_넘어간다(self):
        broken = self.make_run('found')
        later = self.make_run('passed')
        real_run_module = tasks.run_module

        def first_breaks(run):
            if run.pk == broken.pk:
                raise RuntimeError('실패 기록 중 DB 오류')
            return real_run_module(run)

        with patch('scans.tasks.run_module', side_effect=first_breaks):
            with self.assertLogs('scans.tasks', 'ERROR'):
                run_scan(self.scan.pk)

        broken.refresh_from_db()
        later.refresh_from_db()
        self.scan.refresh_from_db()
        self.assertEqual((broken.status, broken.error_message), (ModuleRun.Status.FAILED, tasks.RUNNER_ERROR))
        self.assertEqual(later.status, ModuleRun.Status.PASSED)
        self.assertEqual(self.scan.status, Scan.Status.DONE)

    def test_실행기_자체가_멈춰도_점검은_완료로_끝나지_않은_칸은_실패로_바꾼다(self):
        first = self.make_run('found')
        second = self.make_run('passed')
        real_fail_unfinished = tasks.fail_unfinished
        calls = []

        def flaky(runs):
            # 칸 하나의 실패 기록까지 실패해서 반복 전체가 멈추는 경우를 만든다. 마지막 정리는 정상으로 돈다.
            calls.append(runs)
            if len(calls) == 1:
                raise DatabaseError('DB 연결 끊김')
            return real_fail_unfinished(runs)

        with patch('scans.tasks.run_module', side_effect=RuntimeError('버그')), \
                patch('scans.tasks.fail_unfinished', side_effect=flaky):
            with self.assertLogs('scans.tasks', 'ERROR'), self.assertRaises(DatabaseError):
                run_scan(self.scan.pk)

        self.scan.refresh_from_db()
        self.assertEqual(self.scan.status, Scan.Status.DONE)
        for run in (first, second):
            run.refresh_from_db()
            self.assertEqual((run.status, run.error_message), (ModuleRun.Status.FAILED, tasks.RUNNER_ERROR))

    def test_실행기가_멈춰도_이미_끝난_칸의_결과는_그대로_둔다(self):
        done = self.make_run('found')
        broken = self.make_run('passed')
        real_run_module = tasks.run_module
        real_fail_unfinished = tasks.fail_unfinished

        def second_breaks(run):
            if run.pk == broken.pk:
                raise RuntimeError('버그')
            return real_run_module(run)

        calls = []

        def first_call_breaks(runs):
            calls.append(runs)
            if len(calls) == 1:
                raise DatabaseError('DB 연결 끊김')
            return real_fail_unfinished(runs)

        with patch('scans.tasks.run_module', side_effect=second_breaks), \
                patch('scans.tasks.fail_unfinished', side_effect=first_call_breaks):
            with self.assertLogs('scans.tasks', 'ERROR'), self.assertRaises(DatabaseError):
                run_scan(self.scan.pk)

        done.refresh_from_db()
        broken.refresh_from_db()
        self.assertEqual((done.status, done.finding_count), (ModuleRun.Status.FOUND, 3))
        self.assertEqual(broken.status, ModuleRun.Status.FAILED)

    def cancel_scan(self):
        """web에서 취소 요청이 들어온 것처럼 점검을 취소한다."""
        scan = Scan.objects.get(pk=self.scan.pk)
        scan.cancel()

    def assert_cancelled(self, *runs):
        self.scan.refresh_from_db()
        self.assertEqual(self.scan.status, Scan.Status.CANCELLED)
        for run in runs:
            run.refresh_from_db()
            self.assertEqual(run.status, ModuleRun.Status.CANCELLED)

    def test_시작하기_전에_취소된_점검은_실행하지_않는다(self):
        run = self.make_run('found')
        self.cancel_scan()

        run_scan(self.scan.pk)

        self.assert_cancelled(run)
        self.assertIsNone(run.started_at)
        self.assertFalse(run.findings.exists())

    def test_도구가_도는_중에_취소되면_결과를_저장하지_않고_남은_칸도_실행하지_않는다(self):
        MODULES_BY_KEY['cancel_while_running'] = FakeModule(
            'cancel_while_running', ModuleResult('1.0.0', b'[1]', [finding_data('fp-1')]), during_run=self.cancel_scan,
        )
        running = self.make_run('cancel_while_running')
        later = self.make_run('found')

        run_scan(self.scan.pk)

        self.assert_cancelled(running, later)
        # 취소 뒤에 도구가 결과를 내도 저장하지 않는다.
        self.assertEqual((running.finding_count, running.raw_output_path), (0, ''))
        self.assertFalse(running.findings.exists())
        self.assertIsNone(later.started_at)

    def test_도구를_멈춰서_끝나면_칸은_취소로_남는다(self):
        MODULES_BY_KEY['stopped'] = FakeModule('stopped', error=Cancelled(), during_run=self.cancel_scan)
        run = self.make_run('stopped')

        run_scan(self.scan.pk)

        self.assert_cancelled(run)
        self.assertEqual(run.error_message, '')

    def test_취소한_뒤에_도구가_실패해도_취소를_덮어쓰지_않는다(self):
        MODULES_BY_KEY['fail_after_cancel'] = FakeModule(
            'fail_after_cancel', error=ScanError('trivy 실행에 실패했습니다'), during_run=self.cancel_scan,
        )
        run = self.make_run('fail_after_cancel')

        run_scan(self.scan.pk)

        self.assert_cancelled(run)

    def test_끝난_칸은_취소해도_결과가_남는다(self):
        done = self.make_run('found')
        MODULES_BY_KEY['cancel_while_running'] = FakeModule(
            'cancel_while_running', ModuleResult('1.0.0', b'[]'), during_run=self.cancel_scan,
        )
        self.make_run('cancel_while_running')

        run_scan(self.scan.pk)

        done.refresh_from_db()
        self.assertEqual((done.status, done.finding_count), (ModuleRun.Status.FOUND, 3))

    def test_점검을_시작할_때_신호를_남긴다(self):
        # 칸이 없어서 칸 시작 신호는 없고, 점검 시작 신호만 남는다.
        run_scan(self.scan.pk)

        self.scan.refresh_from_db()
        self.assertIsNotNone(self.scan.heartbeat_at)

    def test_칸을_시작할_때마다_신호를_남긴다(self):
        seen = []

        def record_heartbeat():
            seen.append(Scan.objects.get(pk=self.scan.pk).heartbeat_at)

        MODULES_BY_KEY['first'] = FakeModule('first', ModuleResult('1.0.0', b'[]'), during_run=record_heartbeat)
        MODULES_BY_KEY['second'] = FakeModule('second', ModuleResult('1.0.0', b'[]'), during_run=record_heartbeat)
        first = self.make_run('first')
        second = self.make_run('second')

        run_scan(self.scan.pk)

        first.refresh_from_db()
        second.refresh_from_db()
        self.assertEqual(seen, [first.started_at, second.started_at])

    def test_도구가_도는_동안_취소를_확인하면서_살아_있다는_신호를_남긴다(self):
        long_ago = timezone.now() - timedelta(minutes=10)

        def make_heartbeat_old():
            Scan.objects.filter(pk=self.scan.pk).update(heartbeat_at=long_ago)

        module = MODULES_BY_KEY['checking'] = CheckingModule(before_check=make_heartbeat_old)
        run = self.make_run('checking')

        run_scan(self.scan.pk)

        self.scan.refresh_from_db()
        run.refresh_from_db()
        self.assertEqual(module.answers, [False])
        self.assertGreater(self.scan.heartbeat_at, long_ago)
        self.assertEqual(run.status, ModuleRun.Status.PASSED)

    def test_취소된_칸은_취소를_확인하면_취소됐다고_답한다(self):
        module = MODULES_BY_KEY['checking'] = CheckingModule(before_check=self.cancel_scan)
        run = self.make_run('checking')

        run_scan(self.scan.pk)

        self.assertEqual(module.answers, [True])
        self.assert_cancelled(run)

    def test_worker가_멈춘_것으로_정리된_뒤에는_결과를_저장하지_않고_남은_칸도_실행하지_않는다(self):
        def looks_stopped():
            # 도구가 도는 도중에 신호가 5분 넘게 끊긴 것처럼 만들고 정리 작업을 돌린다(worker가 아주 느렸던 경우).
            Scan.objects.filter(pk=self.scan.pk).update(heartbeat_at=timezone.now() - timedelta(minutes=6))
            with self.assertLogs('scans.tasks', 'WARNING'):
                tasks.cleanup_stale_scans()

        MODULES_BY_KEY['slow'] = FakeModule(
            'slow', ModuleResult('1.0.0', b'[1]', [finding_data('fp-1')]), during_run=looks_stopped,
        )
        slow = self.make_run('slow')
        later = self.make_run('found')

        run_scan(self.scan.pk)

        self.scan.refresh_from_db()
        slow.refresh_from_db()
        later.refresh_from_db()
        self.assertEqual(self.scan.status, Scan.Status.DONE)
        self.assertEqual((slow.status, slow.error_message, slow.finding_count), (ModuleRun.Status.FAILED, tasks.WORKER_LOST, 0))
        self.assertFalse(slow.findings.exists())
        self.assertEqual((later.status, later.error_message), (ModuleRun.Status.FAILED, tasks.WORKER_LOST))
        self.assertIsNone(later.started_at)


class CleanupStaleScansTests(TestCase):
    """worker가 멈춰 끝나지 않은 점검 정리(cleanup_stale_scans)"""

    def setUp(self):
        self.project = Project.objects.create(name='karaoke')
        self.target = make_target(self.project)
        now = timezone.now()
        self.long_ago = now - timedelta(minutes=6)
        self.recently = now - timedelta(minutes=1)

    def make_scan(self, status=Scan.Status.RUNNING, created_at=None, heartbeat_at=None):
        scan = Scan.objects.create(project=self.project)
        # created_at은 만들 때 자동으로 지금이 들어가서, 지난 시각은 만든 뒤에 바꾼다.
        Scan.objects.filter(pk=scan.pk).update(
            status=status, created_at=created_at or self.long_ago, heartbeat_at=heartbeat_at,
        )
        scan.refresh_from_db()
        return scan

    def make_run(self, scan, module, **fields):
        return ModuleRun.objects.create(scan=scan, target=self.target, module=module, **fields)

    def assert_status(self, obj, status, error_message=None):
        obj.refresh_from_db()
        self.assertEqual(obj.status, status)
        if error_message is not None:
            self.assertEqual(obj.error_message, error_message)

    def test_신호가_5분_넘게_끊긴_점검은_완료로_끝나지_않은_칸은_실패로_바꾼다(self):
        scan = self.make_scan(heartbeat_at=self.long_ago)
        done = self.make_run(scan, 'a', status=ModuleRun.Status.PASSED, started_at=self.long_ago, finished_at=self.long_ago)
        running = self.make_run(scan, 'b', status=ModuleRun.Status.RUNNING, started_at=self.long_ago)
        queued = self.make_run(scan, 'c')

        with self.assertLogs('scans.tasks', 'WARNING'):
            tasks.cleanup_stale_scans()

        self.assert_status(scan, Scan.Status.DONE)
        self.assertIsNotNone(scan.finished_at)
        self.assert_status(done, ModuleRun.Status.PASSED, '')
        self.assert_status(running, ModuleRun.Status.FAILED, tasks.WORKER_LOST)
        self.assert_status(queued, ModuleRun.Status.FAILED, tasks.WORKER_LOST)

    def test_신호가_최근에_있으면_그대로_둔다(self):
        scan = self.make_scan(heartbeat_at=self.recently)
        running = self.make_run(scan, 'a', status=ModuleRun.Status.RUNNING, started_at=self.long_ago)
        queued = self.make_run(scan, 'b')

        tasks.cleanup_stale_scans()

        self.assert_status(scan, Scan.Status.RUNNING)
        self.assert_status(running, ModuleRun.Status.RUNNING)
        self.assert_status(queued, ModuleRun.Status.QUEUED)

    def test_오래_대기했어도_방금_실행을_시작한_점검은_그대로_둔다(self):
        # worker가 꺼져 있는 동안 기다리다가 방금 시작한 경우. 시작할 때 신호를 남겨서 만든 시각과 상관없다.
        scan = self.make_scan(created_at=timezone.now() - timedelta(hours=3), heartbeat_at=self.recently)
        queued = self.make_run(scan, 'a')

        tasks.cleanup_stale_scans()

        self.assert_status(scan, Scan.Status.RUNNING)
        self.assert_status(queued, ModuleRun.Status.QUEUED)

    def test_찾은_뒤에_신호가_들어오면_정리하지_않는다(self):
        scan = self.make_scan(heartbeat_at=self.long_ago)
        running = self.make_run(scan, 'a', status=ModuleRun.Status.RUNNING, started_at=self.long_ago)
        calls = []

        @contextmanager
        def heartbeat_arrives(*args, **kwargs):
            # 멈춘 점검을 찾은 뒤, 바꾸기 직전에 worker가 신호를 남긴 경우를 만든다.
            calls.append(args)
            Scan.objects.filter(pk=scan.pk).update(heartbeat_at=timezone.now())
            with transaction.atomic(*args, **kwargs):
                yield

        # tasks.py가 쓰는 transaction 이름만 바꾼다. Django 전체의 transaction.atomic은 그대로 둔다.
        with patch('scans.tasks.transaction', SimpleNamespace(atomic=heartbeat_arrives)):
            tasks.cleanup_stale_scans()

        self.assertEqual(len(calls), 1)
        self.assert_status(scan, Scan.Status.RUNNING)
        self.assert_status(running, ModuleRun.Status.RUNNING)

    def test_신호가_없는_실행_중_점검은_건드리지_않는다(self):
        # 신호 기능을 넣기 전에 시작한 점검. 자동으로 정리하지 않고 화면에서 취소해 푼다.
        scan = self.make_scan(heartbeat_at=None)

        tasks.cleanup_stale_scans()

        self.assert_status(scan, Scan.Status.RUNNING)

    def test_끝났거나_취소된_점검은_건드리지_않는다(self):
        for status in (Scan.Status.DONE, Scan.Status.CANCELLED):
            with self.subTest(status=status):
                scan = self.make_scan(status=status, heartbeat_at=self.long_ago)
                run = self.make_run(scan, 'a', status=ModuleRun.Status.CANCELLED, started_at=self.long_ago)

                tasks.cleanup_stale_scans()

                self.assert_status(scan, status)
                self.assert_status(run, ModuleRun.Status.CANCELLED, '')

    def test_2시간_넘게_대기인_점검은_취소한다(self):
        scan = self.make_scan(status=Scan.Status.QUEUED, created_at=timezone.now() - timedelta(hours=2, minutes=1))
        queued = self.make_run(scan, 'a')

        with self.assertLogs('scans.tasks', 'WARNING'):
            tasks.cleanup_stale_scans()

        self.assert_status(scan, Scan.Status.CANCELLED)
        self.assertIsNotNone(scan.finished_at)
        self.assert_status(queued, ModuleRun.Status.CANCELLED)

    def test_2시간이_안_된_대기_점검은_그대로_둔다(self):
        scan = self.make_scan(status=Scan.Status.QUEUED, created_at=timezone.now() - timedelta(hours=1, minutes=59))
        queued = self.make_run(scan, 'a')

        tasks.cleanup_stale_scans()

        self.assert_status(scan, Scan.Status.QUEUED)
        self.assert_status(queued, ModuleRun.Status.QUEUED)

    def test_정리한_점검의_프로젝트는_바로_새_점검을_시작할_수_있다(self):
        scan = self.make_scan(heartbeat_at=self.long_ago)
        self.make_run(scan, 'a', status=ModuleRun.Status.RUNNING, started_at=self.long_ago)

        with self.assertLogs('scans.tasks', 'WARNING'):
            tasks.cleanup_stale_scans()

        self.assertFalse(self.project.scans.filter(status__in=Scan.ACTIVE).exists())


class BeatScheduleTests(TestCase):
    def test_정리_작업을_1분마다_실행하도록_등록되어_있다(self):
        entry = settings.CELERY_BEAT_SCHEDULE['cleanup-stale-scans']
        self.assertEqual(entry['task'], tasks.cleanup_stale_scans.name)
        self.assertEqual(entry['schedule'], 60.0)
        # worker가 꺼져 있던 동안 쌓인 요청은 버린다.
        self.assertEqual(entry['options']['expires'], 60)


class RunCommandTests(TestCase):
    """도구 실행과 멈추기. 실제 프로세스를 띄워서 확인한다."""

    def setUp(self):
        self.module = ScanModule()
        # 확인 간격과 멈출 때 기다리는 시간을 줄여서 테스트가 빨리 끝나게 한다.
        for name, value in [('CANCEL_CHECK_INTERVAL', 0.1), ('STOP_GRACE', 0.5)]:
            patcher = patch(f'scans.modules.base.{name}', value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def python(self, code):
        return [sys.executable, '-c', code]

    def test_도구의_출력과_종료_코드를_돌려준다(self):
        result = self.module.run_command(self.python('import sys; print("ok"); sys.exit(3)'), never_cancelled)

        self.assertEqual((result.returncode, result.stdout.strip()), (3, b'ok'))

    def test_취소되면_도구를_멈춘다(self):
        started = time.monotonic()
        with self.assertRaises(Cancelled):
            self.module.run_command(self.python('import time; time.sleep(30)'), lambda: True)

        self.assertLess(time.monotonic() - started, 5)

    def test_끝내라는_신호를_무시하는_도구는_강제로_끝낸다(self):
        code = 'import signal, time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(30)'
        started = time.monotonic()
        with self.assertRaises(Cancelled):
            self.module.run_command(self.python(code), lambda: True)

        self.assertLess(time.monotonic() - started, 5)

    def test_도구가_띄운_하위_프로세스까지_멈춘다(self):
        # 하위 프로세스(sleep)가 출력 통로를 물려받는다. 도구만 멈추면 sleep이 끝날 때까지 기다리게 된다.
        code = 'import subprocess, time; subprocess.Popen(["sleep", "30"]); time.sleep(30)'
        started = time.monotonic()
        with self.assertRaises(Cancelled):
            self.module.run_command(self.python(code), lambda: True)

        self.assertLess(time.monotonic() - started, 5)

    def test_취소를_확인하다_오류가_나도_도구를_멈춘다(self):
        def broken():
            raise RuntimeError('DB 연결 끊김')

        started = time.monotonic()
        with self.assertRaisesMessage(RuntimeError, 'DB 연결 끊김'):
            self.module.run_command(self.python('import time; time.sleep(30)'), broken)

        self.assertLess(time.monotonic() - started, 5)

    def test_제한_시간을_넘기면_멈추고_실패한다(self):
        self.module.timeout = 0.3

        with self.assertRaisesMessage(ScanError, '제한 시간'):
            self.module.run_command(self.python('import time; time.sleep(30)'), never_cancelled)

    def test_없는_도구는_실패한다(self):
        with self.assertRaisesMessage(ScanError, '설치되어 있지 않습니다'):
            self.module.run_command(['no-such-tool'], never_cancelled)


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
        return self.module.run(Target(kind='repo', config={'path': str(self.repo)}), never_cancelled)

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
            self.module.run(Target(kind='repo', config={'path': '/no/such/repo'}), never_cancelled)

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

    def fake_run_command(self, args, cancelled):
        """trivy fs는 --output 자리에 결과 파일을 쓰고, trivy version은 버전 JSON을 출력한 것처럼 꾸민다."""
        self.commands.append(args)
        if args[1] == 'fs':
            Path(args[args.index('--output') + 1]).write_bytes(self.report)
            return subprocess.CompletedProcess(args, 0, b'', b'')
        return subprocess.CompletedProcess(args, 0, TRIVY_VERSION_OUTPUT, b'')

    def run_module(self):
        with patch.object(self.module, 'run_command', side_effect=self.fake_run_command):
            return self.module.run(Target(kind='repo', config={'path': str(self.repo)}), never_cancelled)

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
        def failing(args, cancelled):
            return subprocess.CompletedProcess(args, 1, b'', b'FATAL failed to download vulnerability DB')

        with patch.object(self.module, 'run_command', side_effect=failing):
            with self.assertRaisesMessage(ScanError, 'failed to download vulnerability DB'):
                self.module.run(Target(kind='repo', config={'path': str(self.repo)}), never_cancelled)

    def test_폴더가_없으면_실패한다(self):
        with self.assertRaisesMessage(ScanError, '저장소 폴더를 찾을 수 없습니다'):
            self.module.run(Target(kind='repo', config={'path': '/no/such/repo'}), never_cancelled)

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

            result = DependenciesModule().run(Target(kind='repo', config={'path': repo}), never_cancelled)

        self.assertIn('package-lock.json:lodash:4.17.20:CVE-2021-23337', [f.fingerprint for f in result.findings])
        self.assertRegex(result.tool_version, r'^\d+\.\d+\.\d+ \(DB \d{4}-\d{2}-\d{2}\)$')
