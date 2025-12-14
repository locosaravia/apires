from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.authtoken.models import Token
from rest_framework.authtoken.views import ObtainAuthToken
from django.contrib.auth import authenticate
from django.shortcuts import get_object_or_404, redirect
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
    
    @swagger_auto_schema(
        operation_description="Autenticación de usuario y obtención de token",
        operation_summary="Login de usuario",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['username', 'password'],
            properties={
                'username': openapi.Schema(type=openapi.TYPE_STRING, description='Nombre de usuario'),
                'password': openapi.Schema(type=openapi.TYPE_STRING, description='Contraseña'),
            },
        ),
        responses={
            200: openapi.Response(
                description="Login exitoso",
                examples={
                    "application/json": {
                        "token": "9944b09199c62bcf9418ad846dd0e4bbdfc6ee4b",
                        "user_id": 1,
                        "username": "admin",
                        "email": "admin@example.com"
                    }
                }
            ),
            400: "Credenciales faltantes",
            401: "Credenciales inválidas"
        },
        tags=['Autenticación']
    )
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
    
    @swagger_auto_schema(
        operation_description="Cerrar sesión del usuario eliminando su token de autenticación",
        operation_summary="Logout de usuario",
        responses={
            200: openapi.Response(
                description="Sesión cerrada exitosamente",
                examples={"application/json": {"mensaje": "Sesión cerrada exitosamente"}}
            ),
            400: "Error al cerrar sesión",
            401: "No autenticado"
        },
        tags=['Autenticación']
    )
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
    
    @swagger_auto_schema(
        operation_description="Obtener lista de todos los trabajadores con filtros opcionales",
        operation_summary="Listar trabajadores",
        manual_parameters=[
            openapi.Parameter(
                'search', 
                openapi.IN_QUERY, 
                description="Buscar por nombre o apellido", 
                type=openapi.TYPE_STRING,
                required=False
            ),
            openapi.Parameter(
                'activo', 
                openapi.IN_QUERY, 
                description="Filtrar por estado activo (true/false)", 
                type=openapi.TYPE_BOOLEAN,
                required=False
            ),
        ],
        responses={
            200: TrabajadorSerializer(many=True),
            401: "No autenticado"
        },
        tags=['Trabajadores']
    )
    def get(self, request):
        """Listar todos los trabajadores con filtros opcionales"""
        trabajadores = Trabajador.objects.all()
        
        search = request.query_params.get('search', None)
        if search:
            trabajadores = trabajadores.filter(
                nombre__icontains=search
            ) | trabajadores.filter(
                apellido__icontains=search
            )
        
        activo = request.query_params.get('activo', None)
        if activo is not None:
            trabajadores = trabajadores.filter(activo=activo.lower() == 'true')
        
        serializer = TrabajadorSerializer(trabajadores, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    @swagger_auto_schema(
        operation_description="Crear un nuevo trabajador en el sistema",
        operation_summary="Crear trabajador",
        request_body=TrabajadorSerializer,
        responses={
            201: TrabajadorSerializer,
            400: "Datos inválidos",
            401: "No autenticado",
            403: "Sin permisos"
        },
        tags=['Trabajadores']
    )
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
    
    @swagger_auto_schema(
        operation_description="Obtener detalles completos de un trabajador específico",
        operation_summary="Ver trabajador",
        responses={
            200: TrabajadorSerializer,
            404: "Trabajador no encontrado",
            401: "No autenticado"
        },
        tags=['Trabajadores']
    )
    def get(self, request, pk):
        """Obtener detalles de un trabajador"""
        trabajador = get_object_or_404(Trabajador, pk=pk)
        serializer = TrabajadorSerializer(trabajador)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    @swagger_auto_schema(
        operation_description="Actualizar completamente un trabajador (todos los campos requeridos)",
        operation_summary="Actualizar trabajador (completo)",
        request_body=TrabajadorSerializer,
        responses={
            200: TrabajadorSerializer,
            400: "Datos inválidos",
            404: "Trabajador no encontrado",
            401: "No autenticado"
        },
        tags=['Trabajadores']
    )
    def put(self, request, pk):
        """Actualizar un trabajador completamente"""
        trabajador = get_object_or_404(Trabajador, pk=pk)
        serializer = TrabajadorSerializer(trabajador, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    @swagger_auto_schema(
        operation_description="Actualizar parcialmente un trabajador (solo campos enviados)",
        operation_summary="Actualizar trabajador (parcial)",
        request_body=TrabajadorSerializer,
        responses={
            200: TrabajadorSerializer,
            400: "Datos inválidos",
            404: "Trabajador no encontrado"
        },
        tags=['Trabajadores']
    )
    def patch(self, request, pk):
        """Actualizar un trabajador parcialmente"""
        trabajador = get_object_or_404(Trabajador, pk=pk)
        serializer = TrabajadorSerializer(trabajador, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    @swagger_auto_schema(
        operation_description="Eliminar permanentemente un trabajador del sistema",
        operation_summary="Eliminar trabajador",
        responses={
            204: "Trabajador eliminado exitosamente",
            404: "Trabajador no encontrado",
            401: "No autenticado"
        },
        tags=['Trabajadores']
    )
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
    
    @swagger_auto_schema(
        operation_description="Obtener lista de todos los roles disponibles",
        operation_summary="Listar roles",
        manual_parameters=[
            openapi.Parameter('search', openapi.IN_QUERY, description="Buscar por nombre", type=openapi.TYPE_STRING),
            openapi.Parameter('activo', openapi.IN_QUERY, description="Filtrar por estado", type=openapi.TYPE_BOOLEAN),
        ],
        responses={200: RolSerializer(many=True)},
        tags=['Roles']
    )
    def get(self, request):
        roles = Rol.objects.all()
        search = request.query_params.get('search', None)
        if search:
            roles = roles.filter(nombre__icontains=search)
        
        activo = request.query_params.get('activo', None)
        if activo is not None:
            roles = roles.filter(activo=activo.lower() == 'true')
        
        serializer = RolSerializer(roles, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    @swagger_auto_schema(
        operation_description="Crear un nuevo rol en el sistema",
        operation_summary="Crear rol",
        request_body=RolSerializer,
        responses={201: RolSerializer, 400: "Datos inválidos"},
        tags=['Roles']
    )
    def post(self, request):
        serializer = RolSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class RolDetailAPIView(APIView):
    """Vista para ver, editar y eliminar un rol específico"""
    permission_classes = [IsAuthenticated, IsAdminOrReadOnly]
    
    @swagger_auto_schema(
        operation_description="Obtener detalles de un rol específico",
        responses={200: RolSerializer, 404: "Rol no encontrado"},
        tags=['Roles']
    )
    def get(self, request, pk):
        rol = get_object_or_404(Rol, pk=pk)
        serializer = RolSerializer(rol)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    @swagger_auto_schema(
        operation_description="Actualizar completamente un rol",
        request_body=RolSerializer,
        responses={200: RolSerializer, 400: "Datos inválidos"},
        tags=['Roles']
    )
    def put(self, request, pk): 
        rol = get_object_or_404(Rol, pk=pk)
        serializer = RolSerializer(rol, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    @swagger_auto_schema(
        operation_description="Actualizar parcialmente un rol",
        request_body=RolSerializer,
        responses={200: RolSerializer},
        tags=['Roles']
    )
    def patch(self, request, pk):
        rol = get_object_or_404(Rol, pk=pk)
        serializer = RolSerializer(rol, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    @swagger_auto_schema(
        operation_description="Eliminar un rol",
        responses={204: "Rol eliminado", 404: "Rol no encontrado"},
        tags=['Roles']
    )
    def delete(self, request, pk):
        rol = get_object_or_404(Rol, pk=pk)
        rol.delete()
        return Response({'mensaje': 'Rol eliminado exitosamente'}, status=status.HTTP_204_NO_CONTENT)


# ==================== CRUD BUSES ====================

class BusListCreateAPIView(APIView):
    """Vista para listar y crear buses"""
    permission_classes = [IsAuthenticated, CanManageBuses]
    
    @swagger_auto_schema(
        operation_description="Listar todos los buses registrados",
        manual_parameters=[
            openapi.Parameter('search', openapi.IN_QUERY, description="Buscar por patente o modelo", type=openapi.TYPE_STRING),
            openapi.Parameter('activo', openapi.IN_QUERY, description="Filtrar por estado", type=openapi.TYPE_BOOLEAN),
        ],
        responses={200: BusSerializer(many=True)},
        tags=['Buses']
    )
    def get(self, request):
        buses = Bus.objects.all()
        search = request.query_params.get('search', None)
        if search:
            buses = buses.filter(patente__icontains=search) | buses.filter(modelo__icontains=search)
        
        activo = request.query_params.get('activo', None)
        if activo is not None:
            buses = buses.filter(activo=activo.lower() == 'true')
        
        serializer = BusSerializer(buses, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    @swagger_auto_schema(
        operation_description="Registrar un nuevo bus",
        request_body=BusSerializer,
        responses={201: BusSerializer, 400: "Datos inválidos"},
        tags=['Buses']
    )
    def post(self, request):
        serializer = BusSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class BusDetailAPIView(APIView):
    permission_classes = [IsAuthenticated, CanManageBuses]
    
    @swagger_auto_schema(operation_description="Ver detalles de un bus", responses={200: BusSerializer}, tags=['Buses'])
    def get(self, request, pk):
        bus = get_object_or_404(Bus, pk=pk)
        serializer = BusSerializer(bus)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    @swagger_auto_schema(operation_description="Actualizar bus completo", request_body=BusSerializer, responses={200: BusSerializer}, tags=['Buses'])
    def put(self, request, pk):
        bus = get_object_or_404(Bus, pk=pk)
        serializer = BusSerializer(bus, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    @swagger_auto_schema(operation_description="Actualizar bus parcial", request_body=BusSerializer, responses={200: BusSerializer}, tags=['Buses'])
    def patch(self, request, pk):
        bus = get_object_or_404(Bus, pk=pk)
        serializer = BusSerializer(bus, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    @swagger_auto_schema(operation_description="Eliminar bus", responses={204: "Bus eliminado"}, tags=['Buses'])
    def delete(self, request, pk):
        bus = get_object_or_404(Bus, pk=pk)
        bus.delete()
        return Response({'mensaje': 'Bus eliminado exitosamente'}, status=status.HTTP_204_NO_CONTENT)


# ==================== CRUD ESTADO BUS ====================

class EstadoBusListCreateAPIView(APIView):
    permission_classes = [IsAuthenticated, CanManageBuses]
    
    @swagger_auto_schema(
        operation_description="Listar estados de buses",
        manual_parameters=[openapi.Parameter('estado', openapi.IN_QUERY, description="Filtrar por tipo de estado", type=openapi.TYPE_STRING)],
        responses={200: EstadoBusSerializer(many=True)},
        tags=['Estados de Buses']
    )
    def get(self, request):
        estados = EstadoBus.objects.all()
        estado_filter = request.query_params.get('estado', None)
        if estado_filter:
            estados = estados.filter(estado=estado_filter)
        serializer = EstadoBusSerializer(estados, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    @swagger_auto_schema(
        operation_description="Crear estado de bus",
        request_body=EstadoBusSerializer,
        responses={201: EstadoBusSerializer},
        tags=['Estados de Buses']
    )
    def post(self, request):
        serializer = EstadoBusSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class EstadoBusDetailAPIView(APIView):
    permission_classes = [IsAuthenticated, CanManageBuses]
    
    @swagger_auto_schema(responses={200: EstadoBusSerializer}, tags=['Estados de Buses'])
    def get(self, request, pk):
        estado = get_object_or_404(EstadoBus, pk=pk)
        serializer = EstadoBusSerializer(estado)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    @swagger_auto_schema(request_body=EstadoBusSerializer, responses={200: EstadoBusSerializer}, tags=['Estados de Buses'])
    def put(self, request, pk):
        estado = get_object_or_404(EstadoBus, pk=pk)
        serializer = EstadoBusSerializer(estado, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    @swagger_auto_schema(request_body=EstadoBusSerializer, tags=['Estados de Buses'])
    def patch(self, request, pk):
        estado = get_object_or_404(EstadoBus, pk=pk)
        serializer = EstadoBusSerializer(estado, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    @swagger_auto_schema(responses={204: "Eliminado"}, tags=['Estados de Buses'])
    def delete(self, request, pk):
        estado = get_object_or_404(EstadoBus, pk=pk)
        estado.delete()
        return Response({'mensaje': 'Estado de bus eliminado exitosamente'}, status=status.HTTP_204_NO_CONTENT)


# ==================== CRUD ASIGNACIÓN ROL ====================

class AsignacionRolListCreateAPIView(APIView):
    permission_classes = [IsAuthenticated, CanManageAssignments]
    
    @swagger_auto_schema(
        operation_description="Listar asignaciones de roles",
        manual_parameters=[openapi.Parameter('activo', openapi.IN_QUERY, type=openapi.TYPE_BOOLEAN)],
        responses={200: AsignacionRolSerializer(many=True)},
        tags=['Asignaciones de Roles']
    )
    def get(self, request):
        asignaciones = AsignacionRol.objects.all()
        activo = request.query_params.get('activo', None)
        if activo is not None:
            asignaciones = asignaciones.filter(activo=activo.lower() == 'true')
        serializer = AsignacionRolSerializer(asignaciones, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    @swagger_auto_schema(
        operation_description="Crear asignación de rol",
        request_body=AsignacionRolSerializer,
        responses={201: AsignacionRolSerializer},
        tags=['Asignaciones de Roles']
    )
    def post(self, request):
        serializer = AsignacionRolSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class AsignacionRolDetailAPIView(APIView):
    permission_classes = [IsAuthenticated, CanManageAssignments]
    
    @swagger_auto_schema(responses={200: AsignacionRolSerializer}, tags=['Asignaciones de Roles'])
    def get(self, request, pk):
        asignacion = get_object_or_404(AsignacionRol, pk=pk)
        serializer = AsignacionRolSerializer(asignacion)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    @swagger_auto_schema(request_body=AsignacionRolSerializer, tags=['Asignaciones de Roles'])
    def put(self, request, pk):
        asignacion = get_object_or_404(AsignacionRol, pk=pk)
        serializer = AsignacionRolSerializer(asignacion, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    @swagger_auto_schema(request_body=AsignacionRolSerializer, tags=['Asignaciones de Roles'])
    def patch(self, request, pk):
        asignacion = get_object_or_404(AsignacionRol, pk=pk)
        serializer = AsignacionRolSerializer(asignacion, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    @swagger_auto_schema(responses={204: "Eliminado"}, tags=['Asignaciones de Roles'])
    def delete(self, request, pk):
        asignacion = get_object_or_404(AsignacionRol, pk=pk)
        asignacion.delete()
        return Response({'mensaje': 'Asignación de rol eliminada exitosamente'}, status=status.HTTP_204_NO_CONTENT)


# ==================== CRUD ASIGNACIÓN BUS ====================

class AsignacionBusListCreateAPIView(APIView):
    permission_classes = [IsAuthenticated, CanManageAssignments]
    
    @swagger_auto_schema(
        operation_description="Listar asignaciones de buses",
        manual_parameters=[
            openapi.Parameter('activo', openapi.IN_QUERY, type=openapi.TYPE_BOOLEAN),
            openapi.Parameter('turno', openapi.IN_QUERY, type=openapi.TYPE_STRING),
        ],
        responses={200: AsignacionBusSerializer(many=True)},
        tags=['Asignaciones de Buses']
    )
    def get(self, request):
        asignaciones = AsignacionBus.objects.all()
        activo = request.query_params.get('activo', None)
        if activo is not None:
            asignaciones = asignaciones.filter(activo=activo.lower() == 'true')
        turno = request.query_params.get('turno', None)
        if turno:
            asignaciones = asignaciones.filter(turno=turno)
        serializer = AsignacionBusSerializer(asignaciones, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    @swagger_auto_schema(
        operation_description="Crear asignación de bus",
        request_body=AsignacionBusSerializer,
        responses={201: AsignacionBusSerializer},
        tags=['Asignaciones de Buses']
    )
    def post(self, request):
        serializer = AsignacionBusSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class AsignacionBusDetailAPIView(APIView):
    permission_classes = [IsAuthenticated, CanManageAssignments]
    
    @swagger_auto_schema(responses={200: AsignacionBusSerializer}, tags=['Asignaciones de Buses'])
    def get(self, request, pk):
        asignacion = get_object_or_404(AsignacionBus, pk=pk)
        serializer = AsignacionBusSerializer(asignacion)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    @swagger_auto_schema(request_body=AsignacionBusSerializer, tags=['Asignaciones de Buses'])
    def put(self, request, pk):
        asignacion = get_object_or_404(AsignacionBus, pk=pk)
        serializer = AsignacionBusSerializer(asignacion, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    @swagger_auto_schema(request_body=AsignacionBusSerializer, tags=['Asignaciones de Buses'])
    def patch(self, request, pk):
        asignacion = get_object_or_404(AsignacionBus, pk=pk)
        serializer = AsignacionBusSerializer(asignacion, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    @swagger_auto_schema(responses={204: "Eliminado"}, tags=['Asignaciones de Buses'])
    def delete(self, request, pk):
        asignacion = get_object_or_404(AsignacionBus, pk=pk)
        asignacion.delete()
        return Response({'mensaje': 'Asignación de bus eliminada exitosamente'}, status=status.HTTP_204_NO_CONTENT)

# ==================== VISTAS WEB ====================

def web_login_view(request):
    """Vista de redirección a la API browsable"""
    return redirect('/api/trabajadores/')

def api_docs_view(request):
    """Vista de redirección a la documentación"""
    return redirect('/swagger/')