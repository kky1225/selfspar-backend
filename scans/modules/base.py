"""점검 모듈의 공통 틀. 모듈을 새로 만들 때는 ScanModule을 물려받아 key, label, kinds, run을 채운다."""
import os
import signal
import subprocess
import time
from dataclasses import dataclass, field

# 도구가 도는 동안 취소되었는지 확인하는 간격(초)
CANCEL_CHECK_INTERVAL = 2
# 멈추라고 한 도구가 스스로 끝나기를 기다리는 시간(초). 넘기면 강제로 끝낸다.
STOP_GRACE = 5


class ScanError(Exception):
    """도구를 실행하지 못했거나 결과를 읽지 못했을 때. 그 칸은 '실패'가 되고 이 문구가 오류 내용으로 남는다."""


class Cancelled(Exception):
    """점검이 취소되어 도구를 멈췄을 때. 칸은 취소할 때 이미 '취소'로 바뀌어 있어서 따로 저장하지 않는다."""


def never_cancelled():
    """취소되지 않는 실행. 테스트처럼 점검 칸 없이 모듈만 돌릴 때 쓴다."""
    return False


@dataclass
class FindingData:
    """모듈이 도구 결과에서 뽑아낸 발견 하나. 저장할 때 Finding 모델의 칸이 된다."""

    fingerprint: str
    rule_id: str
    title: str
    severity: str
    location: str
    # 비밀 값은 가린 상태여야 한다.
    evidence: str = ''
    extra: dict = field(default_factory=dict)


@dataclass
class ModuleResult:
    tool_version: str
    # 도구가 낸 결과 파일 그대로. 나중에 다시 처리할 수 있게 따로 보관한다.
    raw_output: bytes
    findings: list[FindingData] = field(default_factory=list)


class ScanModule:
    # DB(ModuleRun.module)에 적는 이름. 한 번 정하면 바꾸지 않는다.
    key = ''
    # 화면에 보여 주는 이름
    label = ''
    # 이 모듈을 실행할 대상 종류. 다른 종류의 대상은 '해당 없음'이다.
    kinds = ()
    # 도구 한 번 실행에 허용하는 시간(초)
    timeout = 600

    def applies_to(self, target):
        return target.kind in self.kinds

    def run(self, target, cancelled):
        """대상을 점검하고 ModuleResult를 돌려준다. 실패하면 ScanError를 일으킨다.
        cancelled는 점검이 취소되었는지 알려 주는 함수다. 도구를 실행할 때 run_command에 그대로 넘긴다.
        cancelled를 부를 때마다 worker가 살아 있다는 신호도 남는다. 도구 밖에서 오래 걸리는 처리(몇 분 이상)를 넣을 때는
        중간중간 cancelled()를 불러야 한다. 5분 넘게 부르지 않으면 worker가 멈춘 것으로 보고 칸을 실패로 정리한다."""
        raise NotImplementedError

    def run_command(self, args, cancelled):
        """도구를 실행한다. 셸을 거치지 않고 인자 목록을 그대로 넘겨서, 경로에 특수문자가 있어도 명령이 바뀌지 않는다.
        도구가 도는 동안 잠시마다 취소되었는지 확인하고, 취소되었거나 제한 시간을 넘기면 도구를 멈춘다."""
        try:
            # start_new_session: 도구를 새 프로세스 그룹으로 띄운다. 멈출 때 도구가 띄운 하위 프로세스(예: gitleaks가 부르는 git)까지
            # 그룹째로 멈추기 위해서다. 하위 프로세스가 남아 출력 통로를 쥐고 있으면 결과를 기다리는 쪽이 끝나지 않는다.
            process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        except FileNotFoundError:
            raise ScanError(f'점검 도구가 설치되어 있지 않습니다: {args[0]}')

        deadline = time.monotonic() + self.timeout
        with process:
            try:
                while True:
                    # communicate를 짧게 기다렸다가 다시 부르는 방식은 출력을 잃지 않는다(파이썬 공식 문서의 사용법).
                    try:
                        stdout, stderr = process.communicate(timeout=CANCEL_CHECK_INTERVAL)
                        return subprocess.CompletedProcess(args, process.returncode, stdout, stderr)
                    except subprocess.TimeoutExpired:
                        pass
                    if cancelled():
                        raise Cancelled()
                    if time.monotonic() >= deadline:
                        raise ScanError(f'제한 시간({self.timeout // 60}분)을 넘겨 중단했습니다.')
            except BaseException:
                # 취소·제한 시간뿐 아니라 취소 확인 중 DB 오류 같은 예외로 나갈 때도 도구를 멈춘다.
                # 멈추지 않으면 with를 나갈 때 도구가 스스로 끝날 때까지 시간 제한 없이 기다린다.
                self.stop(process)
                raise

    def stop(self, process):
        """도구 그룹에 끝내라는 신호(SIGTERM)를 보내고, 정리할 시간을 준 뒤에도 안 끝나면 강제로 끝낸다(SIGKILL)."""
        self.signal_group(process, signal.SIGTERM)
        try:
            process.communicate(timeout=STOP_GRACE)
        except subprocess.TimeoutExpired:
            self.signal_group(process, signal.SIGKILL)
            process.communicate()

    def signal_group(self, process, sig):
        try:
            # 새 그룹의 번호는 도구의 프로세스 번호와 같다.
            os.killpg(process.pid, sig)
        except ProcessLookupError:
            # 그룹이 이미 모두 끝났다.
            pass


def last_lines(output, limit=2000):
    """도구가 낸 오류 출력의 끝부분만 남긴다. 원인은 보통 마지막 몇 줄에 있다."""
    text = output.decode(errors='replace').strip()
    return text[-limit:]
