from rest_framework import serializers
from rest_framework.validators import UniqueValidator

from .models import Project


class ProjectSerializer(serializers.ModelSerializer):
    # 모델 칸이 아니라 조회할 때 세서 붙이는 값이다. 방금 등록한 프로젝트처럼 세지 않은 객체는 0이다.
    target_count = serializers.IntegerField(read_only=True, default=0)

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
