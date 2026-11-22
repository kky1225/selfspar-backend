# 점검과 칸의 상태에 '취소'를 추가한다. 선택지(choices)만 바뀌어서 DB 구조는 그대로다.

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('scans', '0003_scan_source_scan'),
    ]

    operations = [
        migrations.AlterField(
            model_name='scan',
            name='status',
            field=models.CharField(
                choices=[('queued', '대기'), ('running', '실행 중'), ('done', '완료'), ('cancelled', '취소')],
                default='queued',
                max_length=10,
                verbose_name='상태',
            ),
        ),
        migrations.AlterField(
            model_name='modulerun',
            name='status',
            field=models.CharField(
                choices=[
                    ('queued', '대기'), ('running', '실행 중'), ('passed', '이상 없음'), ('found', '발견'),
                    ('failed', '실패'), ('cancelled', '취소'),
                ],
                default='queued',
                max_length=10,
                verbose_name='상태',
            ),
        ),
    ]
