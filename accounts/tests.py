from datetime import timedelta

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import Client, TestCase
from django.urls import reverse
from django.utils import timezone

from .models import LoginFailure

PASSWORD = 'correct-horse-battery'


class AuthApiTests(TestCase):
    def setUp(self):
        # 로그인 시도 횟수 기록이 앞 테스트에서 넘어오지 않게 비운다.
        cache.clear()
        self.user = get_user_model().objects.create_user('tester', password=PASSWORD)

    def login(self, username='tester', password=PASSWORD):
        return self.client.post(
            reverse('api_login'),
            {'username': username, 'password': password},
            content_type='application/json',
        )

    def me(self):
        return self.client.get(reverse('api_me'))

    def test_로그인하면_내_정보를_돌려준다(self):
        response = self.login()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {'id': self.user.pk, 'username': 'tester'})
        self.assertEqual(self.me().json()['username'], 'tester')

    def test_비밀번호가_틀리면_400이고_로그인되지_않는다(self):
        response = self.login(password='wrong-password')

        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.me().status_code, 403)

    def test_없는_아이디와_틀린_비밀번호는_같은_응답이다(self):
        no_user = self.login(username='nobody')
        wrong_password = self.login(password='wrong-password')

        self.assertEqual(no_user.status_code, wrong_password.status_code)
        self.assertEqual(no_user.json(), wrong_password.json())

    def test_비밀번호_앞뒤_공백을_지우지_않는다(self):
        response = self.login(password=f' {PASSWORD} ')

        self.assertEqual(response.status_code, 400)

    def test_입력이_비면_400이다(self):
        response = self.client.post(reverse('api_login'), {}, content_type='application/json')

        self.assertEqual(response.status_code, 400)
        self.assertIn('username', response.json())
        self.assertIn('password', response.json())

    def test_비활성_사용자는_로그인할_수_없다(self):
        self.user.is_active = False
        self.user.save()

        self.assertEqual(self.login().status_code, 400)

    def test_로그인하지_않으면_내_정보는_403이다(self):
        self.assertEqual(self.me().status_code, 403)

    def test_로그아웃하면_내_정보는_403이다(self):
        self.login()

        response = self.client.post(reverse('api_logout'))

        self.assertEqual(response.status_code, 204)
        self.assertEqual(self.me().status_code, 403)

    def test_로그인하면_세션_ID가_바뀐다(self):
        session = self.client.session
        session['before_login'] = True
        session.save()
        before = session.session_key

        self.login()

        self.assertNotEqual(self.client.session.session_key, before)

    def test_로그인_시도는_1분에_5번까지만_받는다(self):
        # 계정 잠금과 섞이지 않게, 실패는 없는 아이디로 쌓는다. IP 제한은 아이디와 상관없이 센다.
        for _ in range(5):
            self.assertEqual(self.login(username='nobody').status_code, 400)

        # 6번째는 비밀번호가 맞아도 받지 않는다.
        response = self.login()

        self.assertEqual(response.status_code, 429)
        self.assertEqual(self.me().status_code, 403)


class AccountLockTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user('tester', password=PASSWORD)

    def login(self, username='tester', password=PASSWORD):
        # 계정 잠금만 확인하려고, 요청마다 IP 횟수 제한(1분에 5번) 기록을 비운다.
        cache.clear()
        return self.client.post(
            reverse('api_login'),
            {'username': username, 'password': password},
            content_type='application/json',
        )

    def fail(self, times):
        for _ in range(times):
            response = self.login(password='wrong-password')
        return response

    def expire_lock(self):
        LoginFailure.objects.filter(user=self.user).update(
            locked_until=timezone.now() - timedelta(seconds=1),
        )

    def test_4번까지는_잠기지_않는다(self):
        self.assertEqual(self.fail(4).status_code, 400)

        self.assertEqual(self.login().status_code, 200)

    def test_5번째_실패에서_10분_잠긴다(self):
        response = self.fail(5)

        self.assertEqual(response.status_code, 423)
        self.assertEqual(response.json()['lock_remaining_seconds'], 600)

    def test_잠긴_동안에는_맞는_비밀번호도_거절한다(self):
        self.fail(5)

        response = self.login()

        self.assertEqual(response.status_code, 423)
        self.assertEqual(self.client.get(reverse('api_me')).status_code, 403)

    def test_잠긴_동안의_시도는_실패_횟수에_넣지_않는다(self):
        self.fail(5)
        self.fail(3)

        self.assertEqual(LoginFailure.objects.get(user=self.user).failed_count, 5)

    def test_잠금_시간이_지나면_로그인된다(self):
        self.fail(5)
        self.expire_lock()

        self.assertEqual(self.login().status_code, 200)

    def test_실패가_쌓일수록_잠금_시간이_길어진다(self):
        expected = {5: 600, 6: 600, 9: 600, 10: 1800, 19: 1800, 20: 3600, 21: 3600}
        for count in range(1, 22):
            self.expire_lock()
            response = self.login(password='wrong-password')
            if count in expected:
                with self.subTest(count=count):
                    self.assertEqual(response.status_code, 423)
                    self.assertEqual(response.json()['lock_remaining_seconds'], expected[count])

    def test_로그인에_성공하면_실패_횟수가_초기화된다(self):
        self.fail(4)
        self.login()

        self.assertFalse(LoginFailure.objects.exists())
        self.assertEqual(self.fail(4).status_code, 400)

    def test_없는_아이디는_기록하지_않는다(self):
        for _ in range(5):
            response = self.login(username='nobody', password='wrong-password')

        self.assertEqual(response.status_code, 400)
        self.assertFalse(LoginFailure.objects.exists())

    def test_관리자_화면_로그인에도_잠금이_적용된다(self):
        self.user.is_staff = True
        self.user.is_superuser = True
        self.user.save()
        self.fail(5)

        self.client.post(reverse('admin:login'), {'username': 'tester', 'password': PASSWORD})

        self.assertEqual(self.client.get(reverse('api_me')).status_code, 403)


class AuthCsrfTests(TestCase):
    """테스트 클라이언트는 기본으로 CSRF 검사를 건너뛰어서, 검사를 켠 클라이언트로 확인한다."""

    def setUp(self):
        cache.clear()
        self.user = get_user_model().objects.create_user('tester', password=PASSWORD)
        self.client = Client(enforce_csrf_checks=True)

    def csrf_token(self):
        response = self.client.get(reverse('api_csrf'))
        self.assertEqual(response.status_code, 204)
        return response.cookies['csrftoken'].value

    def login(self, **headers):
        return self.client.post(
            reverse('api_login'),
            {'username': 'tester', 'password': PASSWORD},
            content_type='application/json',
            headers=headers,
        )

    def test_CSRF_토큰_없이_로그인하면_403이다(self):
        response = self.login()

        self.assertEqual(response.status_code, 403)
        self.assertEqual(self.client.get(reverse('api_me')).status_code, 403)

    def test_CSRF_쿠키의_값을_헤더에_담으면_로그인된다(self):
        response = self.login(**{'X-CSRFToken': self.csrf_token()})

        self.assertEqual(response.status_code, 200)

    def test_Vite_프록시를_거친_요청처럼_주소가_같으면_로그인된다(self):
        # vite.config.ts의 changeOrigin: false 상태: Host와 Origin이 둘 다 localhost:5180이다.
        response = self.login(**{
            'X-CSRFToken': self.csrf_token(),
            'Host': 'localhost:5180',
            'Origin': 'http://localhost:5180',
        })

        self.assertEqual(response.status_code, 200)

    def test_다른_사이트에서_보낸_로그인은_토큰이_있어도_막는다(self):
        response = self.login(**{
            'X-CSRFToken': self.csrf_token(),
            'Origin': 'http://evil.example',
        })

        self.assertEqual(response.status_code, 403)

    def test_로그인한_뒤에도_CSRF_토큰_없이는_로그아웃할_수_없다(self):
        self.client.force_login(self.user)

        response = self.client.post(reverse('api_logout'))

        self.assertEqual(response.status_code, 403)
        self.assertEqual(self.client.get(reverse('api_me')).status_code, 200)
