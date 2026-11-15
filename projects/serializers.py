from rest_framework import serializers
from rest_framework.validators import UniqueValidator

from .models import Project, Target
from .validators import (
    TOKEN_LOCATIONS,
    validate_absolute_path,
    validate_apk_path,
    validate_aws_account_id,
    validate_aws_region,
    validate_url_path,
    validate_web_url,
)

STACK_MAX_ITEMS = 20
STACK_ITEM_MAX_LENGTH = 50


class ProjectSerializer(serializers.ModelSerializer):
    # 모델 칸이 아니라 조회할 때 세서 붙이는 값이다. 방금 등록한 프로젝트처럼 세지 않은 객체는 0이다.
    target_count = serializers.IntegerField(read_only=True, default=0)
    # 글자 목록만 받는다. 빈 칸은 받아 두었다가 validate_stack에서 버린다.
    stack = serializers.ListField(child=serializers.CharField(allow_blank=True), required=False)

    class Meta:
        model = Project
        fields = ['id', 'name', 'description', 'stack', 'target_count', 'created_at']
        # 검사 규칙(필수, 100자 이하, 중복 금지)은 모델에서 가져오고, 문구만 바꾼다.
        extra_kwargs = {
            'name': {
                'error_messages': {
                    'required': '이름을 입력하세요.',
                    'blank': '이름을 입력하세요.',
                },
                'validators': [
                    UniqueValidator(
                        queryset=Project.objects.all(),
                        message='같은 이름의 프로젝트가 이미 있습니다.',
                    ),
                ],
            },
        }

    def validate_stack(self, value):
        # 앞뒤 공백은 CharField가 이미 지웠다. 빈 칸을 버리고, 대소문자만 다른 중복은 처음 것만 남긴다.
        stack = []
        seen = set()
        for item in value:
            if not item:
                continue
            if len(item) > STACK_ITEM_MAX_LENGTH:
                raise serializers.ValidationError(f'기술 이름은 {STACK_ITEM_MAX_LENGTH}자 이하로 입력하세요.')
            key = item.casefold()
            if key in seen:
                continue
            seen.add(key)
            stack.append(item)
        if len(stack) > STACK_MAX_ITEMS:
            raise serializers.ValidationError(f'기술 스택은 {STACK_MAX_ITEMS}개까지 입력할 수 있습니다.')
        return stack


def web_url_field(**kwargs):
    return serializers.CharField(max_length=500, validators=[validate_web_url], **kwargs)


# 종류마다 config에 담을 칸과 검사 규칙. 비운 선택 칸(allow_blank)은 검사 규칙을 건너뛴다.
class RepoConfigSerializer(serializers.Serializer):
    path = serializers.CharField(max_length=500, validators=[validate_absolute_path])


class DomainConfigSerializer(serializers.Serializer):
    url = web_url_field()


class ApiConfigSerializer(serializers.Serializer):
    base_url = web_url_field()
    swagger_url = web_url_field(required=False, allow_blank=True)
    login_path = serializers.CharField(max_length=200, required=False, allow_blank=True, validators=[validate_url_path])
    token_location = serializers.ChoiceField(choices=TOKEN_LOCATIONS)


class ApkConfigSerializer(serializers.Serializer):
    path = serializers.CharField(max_length=500, validators=[validate_apk_path])


class CloudConfigSerializer(serializers.Serializer):
    account_id = serializers.CharField(validators=[validate_aws_account_id])
    region = serializers.CharField(validators=[validate_aws_region])


CONFIG_SERIALIZERS = {
    Target.Kind.REPO: RepoConfigSerializer,
    Target.Kind.DOMAIN: DomainConfigSerializer,
    Target.Kind.API: ApiConfigSerializer,
    Target.Kind.APK: ApkConfigSerializer,
    Target.Kind.CLOUD: CloudConfigSerializer,
}


class TargetSerializer(serializers.ModelSerializer):
    # 저장된 값('api', 'prod')과 함께 화면에 보여 줄 이름('API', '운영')도 보낸다.
    kind_label = serializers.CharField(source='get_kind_display', read_only=True)
    environment_label = serializers.CharField(source='get_environment_display', read_only=True)
    # 종류별 칸 검사는 종류를 알아야 해서 validate에서 한다.
    config = serializers.DictField(default=dict)

    class Meta:
        model = Target
        fields = ['id', 'name', 'kind', 'kind_label', 'environment', 'environment_label', 'config', 'created_at']
        extra_kwargs = {
            'name': {'error_messages': {'required': '이름을 입력하세요.', 'blank': '이름을 입력하세요.'}},
        }

    def validate(self, attrs):
        # 대상을 넣을 프로젝트는 입력값이 아니라 주소에서 정해서 view가 넘겨준다.
        project = self.context['project']
        errors = {}

        if Target.objects.filter(project=project, name=attrs['name']).exists():
            errors['name'] = ['이 프로젝트에 같은 이름의 대상이 이미 있습니다.']

        config = CONFIG_SERIALIZERS[attrs['kind']](data=attrs['config'])
        if config.is_valid():
            # 종류에 없는 칸은 버리고, 비운 선택 칸은 저장하지 않는다.
            attrs['config'] = {field: value for field, value in config.validated_data.items() if value}
        else:
            errors['config'] = config.errors

        if errors:
            raise serializers.ValidationError(errors)
        return attrs


class ProjectDetailSerializer(serializers.ModelSerializer):
    # 프로젝트에 속한 대상 목록. 모델의 related_name='targets'로 가져온다.
    targets = TargetSerializer(many=True, read_only=True)

    class Meta:
        model = Project
        fields = ['id', 'name', 'description', 'stack', 'targets', 'created_at']
