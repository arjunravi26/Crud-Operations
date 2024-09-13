# Generated by Django 5.1 on 2024-09-11 10:34

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("user", "0001_initial"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="mymodel",
            name="description",
        ),
        migrations.AddField(
            model_name="mymodel",
            name="email",
            field=models.EmailField(default="", max_length=254, unique=True),
        ),
        migrations.AddField(
            model_name="mymodel",
            name="password",
            field=models.CharField(default="defaultpassword", max_length=150),
        ),
    ]
