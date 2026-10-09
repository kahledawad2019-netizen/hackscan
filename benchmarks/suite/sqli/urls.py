"""Django URL configuration for `django_views`."""

from django.urls import path

from . import django_views

urlpatterns = [
    path("orders/customer", django_views.customer_orders),
    path("orders/<int:order_id>/total", django_views.order_total),
    path("orders/recent", django_views.recent_orders),
    path("reports/region", django_views.region_report),
]
