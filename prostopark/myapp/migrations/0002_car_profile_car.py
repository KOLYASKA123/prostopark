# Generated by Django 4.1.10 on 2023-11-24 13:46

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('myapp', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='Car',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('make', models.CharField(max_length=255, unique=True)),
                ('model', models.CharField(max_length=255)),
            ],
        ),
        migrations.AddField(
            model_name='profile',
            name='car',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to='myapp.car'),
        ),
    ]