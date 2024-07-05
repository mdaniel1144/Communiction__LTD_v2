from django.contrib import admin
from django.urls import path
from app import views

urlpatterns = [
    path('Communication_LTD/Search', views.Search , name="Search"),
    path('Communication_LTD/Customer', views.Customer , name="Customer"),
    path('Communication_LTD/Setting', views.Setting , name="Setting"),
]