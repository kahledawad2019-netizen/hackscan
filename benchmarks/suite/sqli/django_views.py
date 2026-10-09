"""Django views using raw SQL."""

from django.db import connection
from django.http import JsonResponse


def customer_orders(request):
    customer = request.GET.get("customer")
    with connection.cursor() as cursor:
        cursor.execute(  # vuln: sqli
            "SELECT * FROM orders WHERE customer = '{}'".format(customer)
        )
        rows = cursor.fetchall()
    return JsonResponse({"rows": rows})


def order_total(request, order_id):
    with connection.cursor() as cursor:
        cursor.execute("SELECT total FROM orders WHERE id = %s", [order_id])  # safe: sqli
        row = cursor.fetchone()
    return JsonResponse({"total": row[0]})


def recent_orders(request):
    days = request.POST["days"]
    sql = "SELECT * FROM orders WHERE created > now() - interval '" + days + " days'"
    with connection.cursor() as cursor:
        cursor.execute(sql)  # vuln: sqli
        rows = cursor.fetchall()
    return JsonResponse({"rows": rows})


class ReportService:
    """Keeps the request on the instance; the query is built in another method."""

    def __init__(self, request):
        self.region = request.GET.get("region", "")

    def rows(self):
        with connection.cursor() as cursor:
            cursor.execute(f"SELECT * FROM sales WHERE region = '{self.region}'")  # vuln: sqli
            return cursor.fetchall()


def region_report(request):
    return JsonResponse({"rows": ReportService(request).rows()})
