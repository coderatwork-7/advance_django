# Generated by Django 5.1.2 on 2024-10-11 09:39

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='status',
            field=models.BooleanField(default=False),
        ),
    ]
