import subprocess

from django.db import connection
from django.http import HttpResponse


def report(request):
    year = request.GET.get("year")
    with connection.cursor() as cursor:
        cursor.execute("SELECT * FROM sales WHERE year = " + year)  # expect: VH-SQLI-001!
        return HttpResponse(cursor.fetchall())


def export(request):
    fmt = request.POST["format"]
    subprocess.run("convert report." + fmt, shell=True)  # expect: VH-CMDI-001!


def raw_lookup(request, User):
    name = request.GET["name"]
    return User.objects.raw("SELECT * FROM auth_user WHERE username = '%s'" % name)  # expect: VH-SQLI-001!


def safe_report(request):
    year = int(request.GET.get("year", "2024"))
    with connection.cursor() as cursor:
        cursor.execute("SELECT * FROM sales WHERE year = %s" % year)  # expect-suppressed: VH-SQLI-001 taint:sanitized


def helper(cursor, year):
    # not a view: `year` origin unknown within this function -> stays a candidate
    cursor.execute("SELECT * FROM sales WHERE year = " + year)  # expect: VH-SQLI-001
