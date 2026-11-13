from rest_framework import serializers
from rest_framework.validators import UniqueValidator

from .models import Project

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
