"""점검 모듈 목록. 새 모듈을 만들면 여기에 추가한다. 이 순서대로 결과 격자의 열이 된다."""
from .secrets import SecretsModule

MODULES = [
    SecretsModule(),
]

MODULES_BY_KEY = {module.key: module for module in MODULES}
