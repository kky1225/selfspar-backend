from django import forms
from django.core.exceptions import ValidationError

from .models import Target
from .validators import (
    TOKEN_LOCATIONS,
    validate_absolute_path,
    validate_apk_path,
    validate_aws_account_id,
    validate_aws_region,
    validate_url_path,
    validate_web_url,
)


def web_url_field(label, **kwargs):
    return forms.URLField(label=label, assume_scheme='https', validators=[validate_web_url], **kwargs)


class TargetForm(forms.ModelForm):
    """모든 종류에 공통인 칸. 종류별 칸은 아래 클래스에서 추가한다."""

    config_fields = ()  # 이 이름의 칸들을 config JSON에 담는다.

    class Meta:
        model = Target
        fields = ['name', 'environment']

    def clean_name(self):
        name = self.cleaned_data['name']
        # project는 폼 칸이 아니어서 유니크 제약을 Django가 미리 검사하지 않는다.
        if Target.objects.filter(project=self.instance.project, name=name).exists():
            raise ValidationError('이 프로젝트에 같은 이름의 대상이 이미 있습니다.')
        return name

    def save(self, commit=True):
        self.instance.config = {
            field: self.cleaned_data[field]
            for field in self.config_fields
            if self.cleaned_data[field]
        }
        return super().save(commit)


class RepoTargetForm(TargetForm):
    config_fields = ('path',)

    path = forms.CharField(label='저장소 경로', max_length=500, validators=[validate_absolute_path])


class DomainTargetForm(TargetForm):
    config_fields = ('url',)

    url = web_url_field('주소')


class ApiTargetForm(TargetForm):
    config_fields = ('base_url', 'swagger_url', 'login_path', 'token_location')

    base_url = web_url_field('API 기본 주소')
    swagger_url = web_url_field('Swagger 문서 주소', required=False)
    login_path = forms.CharField(
        label='로그인 경로',
        max_length=200,
        required=False,
        validators=[validate_url_path],
    )
    token_location = forms.ChoiceField(
        label='토큰 위치',
        choices=TOKEN_LOCATIONS,
    )


class ApkTargetForm(TargetForm):
    config_fields = ('path',)

    path = forms.CharField(label='APK 파일 경로', max_length=500, validators=[validate_apk_path])


class CloudTargetForm(TargetForm):
    config_fields = ('account_id', 'region')

    account_id = forms.CharField(
        label='AWS 계정 번호',
        validators=[validate_aws_account_id],
    )
    region = forms.CharField(
        label='리전',
        validators=[validate_aws_region],
    )


TARGET_FORMS = {
    Target.Kind.REPO: RepoTargetForm,
    Target.Kind.DOMAIN: DomainTargetForm,
    Target.Kind.API: ApiTargetForm,
    Target.Kind.APK: ApkTargetForm,
    Target.Kind.CLOUD: CloudTargetForm,
}
