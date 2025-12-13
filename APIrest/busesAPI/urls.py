from django.urls import path
from .views import (
    LoginAPIView, LogoutAPIView,
    TrabajadorListCreateAPIView, TrabajadorDetailAPIView,
    RolListCreateAPIView, RolDetailAPIView,
    BusListCreateAPIView, BusDetailAPIView,
    EstadoBusListCreateAPIView, EstadoBusDetailAPIView,
    AsignacionRolListCreateAPIView, AsignacionRolDetailAPIView,
    AsignacionBusListCreateAPIView, AsignacionBusDetailAPIView,
    web_login_view, api_docs_view
)

urlpatterns = [
    # Vista web de login (raíz)
    path('', web_login_view, name='web-login'),
    path('docs/', api_docs_view, name='api-docs'),
    
    # API Autenticación
    path('api/auth/login/', LoginAPIView.as_view(), name='api-login'),
    path('api/auth/logout/', LogoutAPIView.as_view(), name='api-logout'),
    
    # API Trabajadores
    path('api/trabajadores/', TrabajadorListCreateAPIView.as_view(), name='trabajadores-list-create'),
    path('api/trabajadores/<int:pk>/', TrabajadorDetailAPIView.as_view(), name='trabajadores-detail'),
    
    # API Roles
    path('api/roles/', RolListCreateAPIView.as_view(), name='roles-list-create'),
    path('api/roles/<int:pk>/', RolDetailAPIView.as_view(), name='roles-detail'),
    
    # API Buses
    path('api/buses/', BusListCreateAPIView.as_view(), name='buses-list-create'),
    path('api/buses/<int:pk>/', BusDetailAPIView.as_view(), name='buses-detail'),
    
    # API Estados de Buses
    path('api/estados-bus/', EstadoBusListCreateAPIView.as_view(), name='estados-bus-list-create'),
    path('api/estados-bus/<int:pk>/', EstadoBusDetailAPIView.as_view(), name='estados-bus-detail'),
    
    # API Asignaciones de Roles
    path('api/asignaciones-rol/', AsignacionRolListCreateAPIView.as_view(), name='asignaciones-rol-list-create'),
    path('api/asignaciones-rol/<int:pk>/', AsignacionRolDetailAPIView.as_view(), name='asignaciones-rol-detail'),
    
    # API Asignaciones de Buses
    path('api/asignaciones-bus/', AsignacionBusListCreateAPIView.as_view(), name='asignaciones-bus-list-create'),
    path('api/asignaciones-bus/<int:pk>/', AsignacionBusDetailAPIView.as_view(), name='asignaciones-bus-detail'),
]