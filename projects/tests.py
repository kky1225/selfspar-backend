from django.contrib.auth import get_user_model
from django.test import Client, TestCase
from django.urls import reverse

from .models import Project, Target


class ProjectLoginRequiredTests(TestCase):
    def test_로그인하지_않으면_등록_화면에_들어갈_수_없다(self):
        response = self.client.get(reverse('project_create'))

        self.assertRedirects(response, f"{reverse('login')}?next=/projects/new/")

    def test_로그인하지_않으면_등록할_수_없다(self):
        self.client.post(reverse('project_create'), {'name': 'investfeed'})

        self.assertFalse(Project.objects.exists())


class ProjectTests(TestCase):
    def setUp(self):
        user = get_user_model().objects.create_user('tester', password='correct-horse-battery')
        self.client.force_login(user)

    def test_프로젝트가_없으면_안내_문구를_보여_준다(self):
        response = self.client.get(reverse('home'))

        self.assertContains(response, '아직 등록한 프로젝트가 없습니다.')

    def test_등록하면_저장되고_목록으로_돌아간다(self):
        response = self.client.post(reverse('project_create'), {
            'name': 'investfeed',
            'description': '금융 피드 서비스',
            'stack': 'Spring Boot, React',
        })

        self.assertRedirects(response, reverse('home'))
        project = Project.objects.get()
        self.assertEqual(project.name, 'investfeed')
        self.assertEqual(project.description, '금융 피드 서비스')
        self.assertEqual(project.stack, 'Spring Boot, React')

    def test_이름만_입력해도_등록된다(self):
        self.client.post(reverse('project_create'), {'name': 'purefi'})

        self.assertTrue(Project.objects.filter(name='purefi').exists())

    def test_이름이_없으면_등록되지_않는다(self):
        response = self.client.post(reverse('project_create'), {'name': ''})

        self.assertEqual(response.status_code, 200)
        self.assertFalse(Project.objects.exists())

    def test_이름이_같으면_등록되지_않는다(self):
        Project.objects.create(name='investfeed')

        response = self.client.post(reverse('project_create'), {'name': 'investfeed'})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(Project.objects.count(), 1)

    def test_목록은_최근_등록한_프로젝트부터_보여_준다(self):
        Project.objects.create(name='먼저 등록')
        Project.objects.create(name='나중 등록')

        response = self.client.get(reverse('home'))

        names = [project.name for project in response.context['project_list']]
        self.assertEqual(names, ['나중 등록', '먼저 등록'])

    def test_입력값의_HTML은_실행되지_않게_바꿔서_보여_준다(self):
        Project.objects.create(name='<b>굵게</b>')

        response = self.client.get(reverse('home'))

        self.assertContains(response, '&lt;b&gt;굵게&lt;/b&gt;')
        self.assertNotContains(response, '<b>굵게</b>')


class TargetTests(TestCase):
    def setUp(self):
        user = get_user_model().objects.create_user('tester', password='correct-horse-battery')
        self.client.force_login(user)
        self.project = Project.objects.create(name='investfeed')

    def create_url(self, kind):
        return reverse('target_create', args=[self.project.pk, kind])

    def post(self, kind, /, **data):
        return self.client.post(self.create_url(kind), {'name': '대상', 'environment': 'prod', **data})

    def test_로그인하지_않으면_상세_화면에_들어갈_수_없다(self):
        self.client.logout()

        response = self.client.get(reverse('project_detail', args=[self.project.pk]))

        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse('login'), response.url)

    def test_목록에_대상_수를_보여_준다(self):
        Target.objects.create(project=self.project, name='저장소', kind='repo', environment='local')
        Target.objects.create(project=self.project, name='API', kind='api', environment='prod')

        response = self.client.get(reverse('home'))

        self.assertEqual(response.context['project_list'][0].target_count, 2)

    def test_상세_화면에_대상을_보여_준다(self):
        Target.objects.create(project=self.project, name='운영 API', kind='api', environment='prod')

        response = self.client.get(reverse('project_detail', args=[self.project.pk]))

        self.assertContains(response, '운영 API')

    def test_종류_선택_화면에_모든_종류가_있다(self):
        response = self.client.get(reverse('target_kind_select', args=[self.project.pk]))

        for _, label in Target.Kind.choices:
            self.assertContains(response, label)

    def test_없는_종류는_404다(self):
        self.assertEqual(self.client.get(self.create_url('unknown')).status_code, 404)

    def test_없는_프로젝트는_404다(self):
        url = reverse('target_create', args=[self.project.pk + 1, 'repo'])

        self.assertEqual(self.client.get(url).status_code, 404)

    def test_저장소를_등록하면_경로가_config에_저장된다(self):
        response = self.post('repo', path='/Users/me/investfeed')

        self.assertRedirects(response, reverse('project_detail', args=[self.project.pk]))
        target = Target.objects.get()
        self.assertEqual(target.project, self.project)
        self.assertEqual(target.kind, 'repo')
        self.assertEqual(target.config, {'path': '/Users/me/investfeed'})

    def test_API는_비운_선택_칸을_config에_넣지_않는다(self):
        self.post('api', base_url='https://api.example.com', token_location='header')

        self.assertEqual(
            Target.objects.get().config,
            {'base_url': 'https://api.example.com', 'token_location': 'header'},
        )

    def test_localhost_주소도_등록된다(self):
        self.post('domain', url='http://localhost:8080')

        self.assertEqual(Target.objects.get().config, {'url': 'http://localhost:8080'})

    def test_클라우드_계정을_등록한다(self):
        self.post('cloud', account_id='123456789012', region='ap-northeast-2')

        self.assertEqual(
            Target.objects.get().config,
            {'account_id': '123456789012', 'region': 'ap-northeast-2'},
        )

    def test_잘못된_값은_등록되지_않는다(self):
        cases = [
            ('repo', {'path': 'relative/path'}),
            ('repo', {'path': '/Users/me/../secret'}),
            ('domain', {'url': 'ftp://example.com'}),
            ('domain', {'url': 'https://user:pass@example.com'}),
            ('api', {'base_url': 'https://a.com', 'token_location': 'header', 'login_path': 'login'}),
            ('apk', {'path': '/Users/me/app.zip'}),
            ('cloud', {'account_id': '123', 'region': 'ap-northeast-2'}),
            ('cloud', {'account_id': '123456789012', 'region': 'seoul'}),
        ]
        for kind, data in cases:
            with self.subTest(kind=kind, data=data):
                response = self.post(kind, **data)

                self.assertEqual(response.status_code, 200)
                self.assertFalse(Target.objects.exists())

    def test_환경은_정해진_값만_받는다(self):
        response = self.client.post(self.create_url('repo'), {
            'name': '대상',
            'environment': 'unknown',
            'path': '/Users/me/investfeed',
        })

        self.assertEqual(response.status_code, 200)
        self.assertFalse(Target.objects.exists())

    def test_같은_프로젝트에_같은_이름은_등록되지_않는다(self):
        self.post('repo', path='/Users/me/a')

        response = self.post('repo', path='/Users/me/b')

        self.assertEqual(response.status_code, 200)
        self.assertEqual(Target.objects.count(), 1)

    def test_다른_프로젝트에는_같은_이름을_쓸_수_있다(self):
        other = Project.objects.create(name='karasearch')
        Target.objects.create(project=other, name='대상', kind='repo', environment='local')

        self.post('repo', path='/Users/me/a')

        self.assertEqual(Target.objects.filter(project=self.project).count(), 1)

    def test_입력값으로_프로젝트와_종류를_바꿀_수_없다(self):
        other = Project.objects.create(name='karasearch')

        self.post('repo', path='/Users/me/a', project=other.pk, kind='cloud')

        target = Target.objects.get()
        self.assertEqual(target.project, self.project)
        self.assertEqual(target.kind, 'repo')


class ProjectListApiTests(TestCase):
    def setUp(self):
        self.url = reverse('api_project_list')
        self.user = get_user_model().objects.create_user('tester', password='correct-horse-battery')

    def test_로그인하지_않으면_403이고_데이터를_주지_않는다(self):
        Project.objects.create(name='investfeed')

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 403)
        self.assertNotContains(response, 'investfeed', status_code=403)

    def test_프로젝트_목록을_JSON으로_돌려준다(self):
        self.client.force_login(self.user)
        project = Project.objects.create(name='investfeed', description='금융', stack='Spring Boot')
        Target.objects.create(project=project, name='운영 API', kind='api', environment='prod')

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'application/json')
        item = response.json()[0]
        self.assertEqual(item['id'], project.pk)
        self.assertEqual(item['name'], 'investfeed')
        self.assertEqual(item['description'], '금융')
        self.assertEqual(item['stack'], 'Spring Boot')
        self.assertEqual(item['target_count'], 1)
        self.assertIn('created_at', item)

    def test_최근_등록한_프로젝트부터_돌려준다(self):
        self.client.force_login(self.user)
        Project.objects.create(name='먼저 등록')
        Project.objects.create(name='나중 등록')

        response = self.client.get(self.url)

        self.assertEqual([item['name'] for item in response.json()], ['나중 등록', '먼저 등록'])


class ProjectCreateApiTests(TestCase):
    def setUp(self):
        self.url = reverse('api_project_list')
        self.user = get_user_model().objects.create_user('tester', password='correct-horse-battery')
        self.client.force_login(self.user)

    def create(self, data, client=None):
        return (client or self.client).post(self.url, data, content_type='application/json')

    def test_등록하면_201이고_저장된다(self):
        response = self.create({
            'name': 'investfeed',
            'description': '금융 피드 서비스',
            'stack': 'Spring Boot, React',
        })

        self.assertEqual(response.status_code, 201)
        project = Project.objects.get()
        self.assertEqual(project.name, 'investfeed')
        self.assertEqual(project.description, '금융 피드 서비스')
        self.assertEqual(project.stack, 'Spring Boot, React')
        body = response.json()
        self.assertEqual(body['id'], project.pk)
        self.assertEqual(body['name'], 'investfeed')
        self.assertEqual(body['target_count'], 0)
        self.assertIn('created_at', body)

    def test_이름만_입력해도_등록된다(self):
        response = self.create({'name': 'purefi'})

        self.assertEqual(response.status_code, 201)
        self.assertTrue(Project.objects.filter(name='purefi').exists())

    def test_이름이_비면_400이다(self):
        for data in ({}, {'name': ''}, {'name': '   '}):
            with self.subTest(data=data):
                response = self.create(data)

                self.assertEqual(response.status_code, 400)
                self.assertEqual(response.json()['name'], ['이름을 입력하세요.'])
        self.assertFalse(Project.objects.exists())

    def test_이름이_같으면_400이다(self):
        Project.objects.create(name='investfeed')

        response = self.create({'name': 'investfeed'})

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()['name'], ['같은 이름의 프로젝트가 이미 있습니다.'])
        self.assertEqual(Project.objects.count(), 1)

    def test_이름이_100자를_넘으면_400이다(self):
        self.assertEqual(self.create({'name': 'a' * 100}).status_code, 201)

        response = self.create({'name': 'b' * 101})

        self.assertEqual(response.status_code, 400)
        self.assertIn('name', response.json())
        self.assertEqual(Project.objects.count(), 1)

    def test_읽기_전용_칸은_보내도_무시된다(self):
        response = self.create({
            'name': 'investfeed',
            'id': 999,
            'target_count': 5,
            'created_at': '2000-01-01T00:00:00Z',
        })

        self.assertEqual(response.status_code, 201)
        project = Project.objects.get()
        self.assertNotEqual(project.pk, 999)
        self.assertNotEqual(project.created_at.year, 2000)
        self.assertEqual(response.json()['target_count'], 0)

    def test_로그인하지_않으면_403이고_저장되지_않는다(self):
        self.client.logout()

        response = self.create({'name': 'investfeed'})

        self.assertEqual(response.status_code, 403)
        self.assertFalse(Project.objects.exists())

    def test_CSRF_토큰_없이_보내면_403이고_저장되지_않는다(self):
        # 테스트 클라이언트는 기본으로 CSRF 검사를 건너뛰어서, 검사를 켠 클라이언트로 확인한다.
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.user)

        response = self.create({'name': 'investfeed'}, client=client)

        self.assertEqual(response.status_code, 403)
        self.assertFalse(Project.objects.exists())
