# Generated by Django 5.1.4 on 2025-05-25 21:32

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0010_alert'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='LostFoundItem',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('description', models.TextField()),
                ('item_type', models.CharField(choices=[('Lost', 'Lost'), ('Found', 'Found')], max_length=10)),
                ('location', models.CharField(blank=True, max_length=255, null=True)),
                ('date_reported', models.DateTimeField(auto_now_add=True)),
                ('contact_info', models.CharField(blank=True, max_length=255, null=True)),
                ('sender', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]
