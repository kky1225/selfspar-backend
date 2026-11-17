# Finding.tasks를 runs로 이름만 바꾼다. 연결 테이블 findings_finding_tasks → findings_finding_runs

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('findings', '0001_initial'),
        ('scans', '0002_rename_scantask_modulerun'),
    ]

    operations = [
        migrations.RenameField(model_name='finding', old_name='tasks', new_name='runs'),
        migrations.AlterField(
            model_name='finding',
            name='runs',
            field=models.ManyToManyField(related_name='findings', to='scans.modulerun', verbose_name='본 모듈 실행'),
        ),
    ]
