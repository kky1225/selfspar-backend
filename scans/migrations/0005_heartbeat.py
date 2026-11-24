# worker가 멈춘 점검을 찾아 정리하려고, 점검에 마지막 신호 시각을 남긴다.

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('scans', '0004_cancelled_status'),
    ]

    operations = [
        migrations.AddField(
            model_name='scan',
            name='heartbeat_at',
            field=models.DateTimeField(blank=True, null=True, verbose_name='마지막 신호'),
        ),
    ]
