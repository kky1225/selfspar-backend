# 발견에 상태(미해결·해결됨·오탐·위험 수용)를 두고, 상태가 바뀐 기록을 쌓는 표를 만든다.
# 이미 있는 발견은 모두 미해결로 시작한다.

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


STATUS_CHOICES = [('open', '미해결'), ('fixed', '해결됨'), ('false_positive', '오탐'), ('risk_accepted', '위험 수용')]


class Migration(migrations.Migration):

    dependencies = [
        ('findings', '0002_rename_finding_tasks_runs'),
        ('scans', '0005_heartbeat'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.AddField(
            model_name='finding',
            name='status',
            field=models.CharField(choices=STATUS_CHOICES, default='open', max_length=20, verbose_name='상태'),
        ),
        migrations.AddField(
            model_name='finding',
            name='accepted_until',
            field=models.DateField(blank=True, null=True, verbose_name='위험 수용 만료일'),
        ),
        migrations.CreateModel(
            name='FindingEvent',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('from_status', models.CharField(choices=STATUS_CHOICES, max_length=20, verbose_name='이전 상태')),
                ('to_status', models.CharField(choices=STATUS_CHOICES, max_length=20, verbose_name='바뀐 상태')),
                ('reason', models.CharField(blank=True, max_length=280, verbose_name='사유')),
                ('accepted_until', models.DateField(blank=True, null=True, verbose_name='위험 수용 만료일')),
                ('created_at', models.DateTimeField(auto_now_add=True, verbose_name='바뀐 시각')),
                ('finding', models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE, related_name='events', to='findings.finding',
                )),
                ('run', models.ForeignKey(
                    blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL,
                    related_name='finding_events', to='scans.modulerun', verbose_name='바뀐 칸',
                )),
                ('user', models.ForeignKey(
                    blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL,
                    to=settings.AUTH_USER_MODEL, verbose_name='바꾼 사람',
                )),
            ],
            options={
                'verbose_name': '발견 상태 이력',
                'ordering': ['-created_at', '-id'],
            },
        ),
    ]
