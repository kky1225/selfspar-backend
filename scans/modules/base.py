"""점검 모듈의 공통 틀. 모듈을 새로 만들 때는 ScanModule을 물려받아 key, label, kinds, run을 채운다."""
import subprocess
from dataclasses import dataclass


class ScanError(Exception):
    """도구를 실행하지 못했거나 결과를 읽지 못했을 때. 그 칸은 '실패'가 되고 이 문구가 오류 내용으로 남는다."""


@dataclass
class ModuleResult:
    finding_count: int
    tool_version: str
    # 도구가 낸 결과 파일 그대로. 나중에 다시 처리할 수 있게 따로 보관한다.
    raw_output: bytes


class ScanModule:
    # DB(ScanTask.module)에 적는 이름. 한 번 정하면 바꾸지 않는다.
    key = ''
    # 화면에 보여 주는 이름
    label = ''
    # 이 모듈을 실행할 대상 종류. 다른 종류의 대상은 '해당 없음'이다.
    kinds = ()
    # 도구 한 번 실행에 허용하는 시간(초)
    timeout = 600

    def applies_to(self, target):
        return target.kind in self.kinds

    def run(self, target):
        """대상을 점검하고 ModuleResult를 돌려준다. 실패하면 ScanError를 일으킨다."""
        raise NotImplementedError

    def run_command(self, args):
        """도구를 실행한다. 셸을 거치지 않고 인자 목록을 그대로 넘겨서, 경로에 특수문자가 있어도 명령이 바뀌지 않는다."""
        try:
            return subprocess.run(args, capture_output=True, timeout=self.timeout)
        except FileNotFoundError:
            raise ScanError(f'점검 도구가 설치되어 있지 않습니다: {args[0]}')
        except subprocess.TimeoutExpired:
            raise ScanError(f'제한 시간({self.timeout // 60}분)을 넘겨 중단했습니다.')


def last_lines(output, limit=2000):
    """도구가 낸 오류 출력의 끝부분만 남긴다. 원인은 보통 마지막 몇 줄에 있다."""
    text = output.decode(errors='replace').strip()
    return text[-limit:]
