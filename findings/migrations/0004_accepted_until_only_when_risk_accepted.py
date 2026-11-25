# 위험 수용일 때만 만료일이 있도록 DB에서도 막는다. 지금 있는 발견은 모두 만료일이 비어 있고 위험 수용이 아니라서 그대로 통과한다.

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('findings', '0003_finding_status_findingevent'),
    ]

    operations = [
        migrations.AddConstraint(
            model_name='finding',
            constraint=models.CheckConstraint(
                condition=(
                    models.Q(status='risk_accepted', accepted_until__isnull=False)
                    | (~models.Q(status='risk_accepted') & models.Q(accepted_until__isnull=True))
                ),
                name='accepted_until_only_when_risk_accepted',
            ),
        ),
    ]
