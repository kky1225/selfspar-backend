# ScanTask를 ModuleRun으로 이름만 바꾼다. 데이터는 그대로 둔다.
# related_name도 함께 바뀌어서 makemigrations가 이름 변경으로 알아보지 못하고
# 테이블을 지우고 새로 만들려고 하므로 직접 작성했다.

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('projects', '0004_testaccount'),
        ('scans', '0001_initial'),
        # findings가 ScanTask를 가리키는 다대다를 먼저 만든 뒤에 이름을 바꿔야 연결 테이블의 칸 이름도 함께 바뀐다.
        ('findings', '0001_initial'),
    ]

    operations = [
        # 테이블 scans_scantask → scans_modulerun, 연결 테이블의 칸 scantask_id → modulerun_id
        migrations.RenameModel(old_name='ScanTask', new_name='ModuleRun'),
        migrations.AlterModelOptions(
            name='modulerun',
            options={'ordering': ['id'], 'verbose_name': '모듈 실행'},
        ),
        # related_name은 파이썬 쪽 이름이라 DB는 바뀌지 않는다.
        migrations.AlterField(
            model_name='modulerun',
            name='scan',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='runs', to='scans.scan'),
        ),
        migrations.AlterField(
            model_name='modulerun',
            name='target',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='module_runs', to='projects.target'),
        ),
        migrations.RemoveConstraint(model_name='modulerun', name='unique_task_per_scan'),
        migrations.AddConstraint(
            model_name='modulerun',
            constraint=models.UniqueConstraint(fields=('scan', 'target', 'module'), name='unique_run_per_scan'),
        ),
    ]
