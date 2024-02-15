# Generated by Django 4.1.10 on 2023-11-24 14:35

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('myapp', '0002_car_profile_car'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='car',
            name='make',
        ),
        migrations.RemoveField(
            model_name='car',
            name='model',
        ),
        migrations.AddField(
            model_name='car',
            name='body',
            field=models.CharField(max_length=50, null=True, unique=True),
        ),
    ]