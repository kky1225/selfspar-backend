import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('scans', '0002_rename_scantask_modulerun'),
    ]

    operations = [
        migrations.AddField(
            model_name='scan',
            name='source_scan',
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.CASCADE,
                related_name='rescans',
                to='scans.scan',
                verbose_name='다시 점검한 점검',
            ),
        ),
    ]
