from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.authtoken.models import Token
from rest_framework.authtoken.views import ObtainAuthToken
from django.contrib.auth import authenticate, login
from django.shortcuts import get_object_or_404, render, redirect
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from .permissions import IsAdminOrReadOnly, CanManageWorkers, CanManageBuses, CanManageAssignments
from .models import Trabajador, Rol, Bus, EstadoBus, AsignacionRol, AsignacionBus
from .serializers import (
    TrabajadorSerializer, RolSerializer, BusSerializer,
    EstadoBusSerializer, AsignacionRolSerializer, AsignacionBusSerializer
)

# ==================== AUTENTICACIÓN ====================

class LoginAPIView(ObtainAuthToken):
    """Vista para login y obtención de token"""
    permission_classes = [AllowAny]
    
    def post(self, request, *args, **kwargs):
        username = request.data.get('username')
        password = request.data.get('password')
        
        if not username or not password:
            return Response(
                {'error': 'Se requiere username y password'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        user = authenticate(username=username, password=password)
        
        if user:
            token, created = Token.objects.get_or_create(user=user)
            return Response({
                'token': token.key,
                'user_id': user.pk,
                'username': user.username,
                'email': user.email
            })
        
        return Response(
            {'error': 'Credenciales inválidas'},
            status=status.HTTP_401_UNAUTHORIZED
        )


class LogoutAPIView(APIView):
    """Vista para logout (eliminar token)"""
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        try:
            request.user.auth_token.delete()
            return Response(
                {'mensaje': 'Sesión cerrada exitosamente'},
                status=status.HTTP_200_OK
            )
        except Exception as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )


# ==================== CRUD TRABAJADORES ====================

class TrabajadorListCreateAPIView(APIView):
    """Vista para listar y crear trabajadores"""
    permission_classes = [IsAuthenticated, CanManageWorkers]
    
    def get(self, request):
        """Listar todos los trabajadores con filtros opcionales"""
        trabajadores = Trabajador.objects.all()
        
        # Filtro por búsqueda
        search = request.query_params.get('search', None)
        if search:
            trabajadores = trabajadores.filter(
                nombre__icontains=search
            ) | trabajadores.filter(
                apellido__icontains=search
            )
        
        # Filtro por estado
        activo = request.query_params.get('activo', None)
        if activo is not None:
            trabajadores = trabajadores.filter(activo=activo.lower() == 'true')
        
        serializer = TrabajadorSerializer(trabajadores, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    def post(self, request):
        """Crear un nuevo trabajador"""
        serializer = TrabajadorSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class TrabajadorDetailAPIView(APIView):
    """Vista para ver, editar y eliminar un trabajador específico"""
    permission_classes = [IsAuthenticated, CanManageWorkers]
    
    def get(self, request, pk):
        """Obtener detalles de un trabajador"""
        trabajador = get_object_or_404(Trabajador, pk=pk)
        serializer = TrabajadorSerializer(trabajador)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    def put(self, request, pk):
        """Actualizar un trabajador completamente"""
        trabajador = get_object_or_404(Trabajador, pk=pk)
        serializer = TrabajadorSerializer(trabajador, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def patch(self, request, pk):
        """Actualizar un trabajador parcialmente"""
        trabajador = get_object_or_404(Trabajador, pk=pk)
        serializer = TrabajadorSerializer(trabajador, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def delete(self, request, pk):
        """Eliminar un trabajador"""
        trabajador = get_object_or_404(Trabajador, pk=pk)
        trabajador.delete()
        return Response(
            {'mensaje': 'Trabajador eliminado exitosamente'},
            status=status.HTTP_204_NO_CONTENT
        )


# ==================== CRUD ROLES ====================

class RolListCreateAPIView(APIView):
    """Vista para listar y crear roles"""
    permission_classes = [IsAuthenticated, IsAdminOrReadOnly]
    
    def get(self, request):
        """Listar todos los roles"""
        roles = Rol.objects.all()
        
        # Filtro por búsqueda
        search = request.query_params.get('search', None)
        if search:
            roles = roles.filter(nombre__icontains=search)
        
        # Filtro por estado
        activo = request.query_params.get('activo', None)
        if activo is not None:
            roles = roles.filter(activo=activo.lower() == 'true')
        
        serializer = RolSerializer(roles, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    def post(self, request):
        """Crear un nuevo rol"""
        serializer = RolSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class RolDetailAPIView(APIView):
    """Vista para ver, editar y eliminar un rol específico"""
    permission_classes = [IsAuthenticated, IsAdminOrReadOnly]
    
    def get(self, request, pk):
        """Obtener detalles de un rol"""
        rol = get_object_or_404(Rol, pk=pk)
        serializer = RolSerializer(rol)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    def put(self, request, pk): 
        """Actualizar un rol completamente"""
        rol = get_object_or_404(Rol, pk=pk)
        serializer = RolSerializer(rol, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def patch(self, request, pk):
        """Actualizar un rol parcialmente"""
        rol = get_object_or_404(Rol, pk=pk)
        serializer = RolSerializer(rol, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def delete(self, request, pk):
        """Eliminar un rol"""
        rol = get_object_or_404(Rol, pk=pk)
        rol.delete()
        return Response(
            {'mensaje': 'Rol eliminado exitosamente'},
            status=status.HTTP_204_NO_CONTENT
        )


# ==================== CRUD BUSES ====================

class BusListCreateAPIView(APIView):
    """Vista para listar y crear buses"""
    permission_classes = [IsAuthenticated, CanManageBuses]
    
    def get(self, request):
        """Listar todos los buses"""
        buses = Bus.objects.all()
        
        # Filtro por búsqueda
        search = request.query_params.get('search', None)
        if search:
            buses = buses.filter(patente__icontains=search) | buses.filter(modelo__icontains=search)
        
        # Filtro por estado
        activo = request.query_params.get('activo', None)
        if activo is not None:
            buses = buses.filter(activo=activo.lower() == 'true')
        
        serializer = BusSerializer(buses, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    def post(self, request):
        """Crear un nuevo bus"""
        serializer = BusSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class BusDetailAPIView(APIView):
    """Vista para ver, editar y eliminar un bus específico"""
    permission_classes = [IsAuthenticated, CanManageBuses]
    
    def get(self, request, pk):
        """Obtener detalles de un bus"""
        bus = get_object_or_404(Bus, pk=pk)
        serializer = BusSerializer(bus)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    def put(self, request, pk):
        """Actualizar un bus completamente"""
        bus = get_object_or_404(Bus, pk=pk)
        serializer = BusSerializer(bus, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def patch(self, request, pk):
        """Actualizar un bus parcialmente"""
        bus = get_object_or_404(Bus, pk=pk)
        serializer = BusSerializer(bus, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def delete(self, request, pk):
        """Eliminar un bus"""
        bus = get_object_or_404(Bus, pk=pk)
        bus.delete()
        return Response(
            {'mensaje': 'Bus eliminado exitosamente'},
            status=status.HTTP_204_NO_CONTENT
        )


# ==================== CRUD ESTADO BUS ====================

class EstadoBusListCreateAPIView(APIView):
    """Vista para listar y crear estados de buses"""
    permission_classes = [IsAuthenticated, CanManageBuses]
    
    def get(self, request):
        """Listar todos los estados de buses"""
        estados = EstadoBus.objects.all()
        
        # Filtro por estado
        estado_filter = request.query_params.get('estado', None)
        if estado_filter:
            estados = estados.filter(estado=estado_filter)
        
        serializer = EstadoBusSerializer(estados, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    def post(self, request):
        """Crear un nuevo estado de bus"""
        serializer = EstadoBusSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class EstadoBusDetailAPIView(APIView):
    """Vista para ver, editar y eliminar un estado de bus específico"""
    permission_classes = [IsAuthenticated, CanManageBuses]
    
    def get(self, request, pk):
        """Obtener detalles de un estado de bus"""
        estado = get_object_or_404(EstadoBus, pk=pk)
        serializer = EstadoBusSerializer(estado)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    def put(self, request, pk):
        """Actualizar un estado de bus completamente"""
        estado = get_object_or_404(EstadoBus, pk=pk)
        serializer = EstadoBusSerializer(estado, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def patch(self, request, pk):
        """Actualizar un estado de bus parcialmente"""
        estado = get_object_or_404(EstadoBus, pk=pk)
        serializer = EstadoBusSerializer(estado, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def delete(self, request, pk):
        """Eliminar un estado de bus"""
        estado = get_object_or_404(EstadoBus, pk=pk)
        estado.delete()
        return Response(
            {'mensaje': 'Estado de bus eliminado exitosamente'},
            status=status.HTTP_204_NO_CONTENT
        )


# ==================== CRUD ASIGNACIÓN ROL ====================

class AsignacionRolListCreateAPIView(APIView):
    """Vista para listar y crear asignaciones de roles"""
    permission_classes = [IsAuthenticated, CanManageAssignments]
    
    def get(self, request):
        """Listar todas las asignaciones de roles"""
        asignaciones = AsignacionRol.objects.all()
        
        # Filtro por estado
        activo = request.query_params.get('activo', None)
        if activo is not None:
            asignaciones = asignaciones.filter(activo=activo.lower() == 'true')
        
        serializer = AsignacionRolSerializer(asignaciones, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    def post(self, request):
        """Crear una nueva asignación de rol"""
        serializer = AsignacionRolSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class AsignacionRolDetailAPIView(APIView):
    """Vista para ver, editar y eliminar una asignación de rol específica"""
    permission_classes = [IsAuthenticated, CanManageAssignments]
    
    def get(self, request, pk):
        """Obtener detalles de una asignación de rol"""
        asignacion = get_object_or_404(AsignacionRol, pk=pk)
        serializer = AsignacionRolSerializer(asignacion)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    def put(self, request, pk):
        """Actualizar una asignación de rol completamente"""
        asignacion = get_object_or_404(AsignacionRol, pk=pk)
        serializer = AsignacionRolSerializer(asignacion, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def patch(self, request, pk):
        """Actualizar una asignación de rol parcialmente"""
        asignacion = get_object_or_404(AsignacionRol, pk=pk)
        serializer = AsignacionRolSerializer(asignacion, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def delete(self, request, pk):
        """Eliminar una asignación de rol"""
        asignacion = get_object_or_404(AsignacionRol, pk=pk)
        asignacion.delete()
        return Response(
            {'mensaje': 'Asignación de rol eliminada exitosamente'},
            status=status.HTTP_204_NO_CONTENT
        )


# ==================== CRUD ASIGNACIÓN BUS ====================

class AsignacionBusListCreateAPIView(APIView):
    """Vista para listar y crear asignaciones de buses"""
    permission_classes = [IsAuthenticated, CanManageAssignments]
    
    def get(self, request):
        """Listar todas las asignaciones de buses"""
        asignaciones = AsignacionBus.objects.all()
        
        # Filtro por estado
        activo = request.query_params.get('activo', None)
        if activo is not None:
            asignaciones = asignaciones.filter(activo=activo.lower() == 'true')
        
        # Filtro por turno
        turno = request.query_params.get('turno', None)
        if turno:
            asignaciones = asignaciones.filter(turno=turno)
        
        serializer = AsignacionBusSerializer(asignaciones, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    def post(self, request):
        """Crear una nueva asignación de bus"""
        serializer = AsignacionBusSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class AsignacionBusDetailAPIView(APIView):
    """Vista para ver, editar y eliminar una asignación de bus específica"""
    permission_classes = [IsAuthenticated, CanManageAssignments]
    
    def get(self, request, pk):
        """Obtener detalles de una asignación de bus"""
        asignacion = get_object_or_404(AsignacionBus, pk=pk)
        serializer = AsignacionBusSerializer(asignacion)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    def put(self, request, pk):
        """Actualizar una asignación de bus completamente"""
        asignacion = get_object_or_404(AsignacionBus, pk=pk)
        serializer = AsignacionBusSerializer(asignacion, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def patch(self, request, pk):
        """Actualizar una asignación de bus parcialmente"""
        asignacion = get_object_or_404(AsignacionBus, pk=pk)
        serializer = AsignacionBusSerializer(asignacion, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def delete(self, request, pk):
        """Eliminar una asignación de bus"""
        asignacion = get_object_or_404(AsignacionBus, pk=pk)
        asignacion.delete()
        return Response(
            {'mensaje': 'Asignación de bus eliminada exitosamente'},
            status=status.HTTP_204_NO_CONTENT
        )

# ==================== VISTAS WEB DE LOGIN ====================

from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login
from django.contrib import messages
from django.views.decorators.csrf import csrf_protect

def web_login_view(request):
    """Vista de redirección a la API browsable"""
    return redirect('/api/trabajadores/')


def api_docs_view(request):
    """Vista de redirección a la documentación"""
    return redirect('/api/trabajadores/')