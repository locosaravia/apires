 Descripción
API REST desarrollada con Django REST Framework para la gestión integral de un sistema de buses, incluyendo administración de trabajadores, roles, buses, estados y asignaciones.

Tecnologías Utilizadas

Backend Framework: Django 5.2.6
API Framework: Django REST Framework 3.14+
Base de Datos: MySQL 8.0+
Autenticación: Token Authentication (DRF)
Documentación: Swagger/OpenAPI (drf-yasg)
CORS: django-cors-headers
Python: 3.10+

Dependencias Principales

Django==5.2.6
djangorestframework==3.14.0
django-cors-headers==4.3.1
drf-yasg==1.21.7
PyMySQL==1.1.0

Instalación y Configuración

1. Requisitos Previos

Python 3.10 o superior
MySQL 8.0 o superior
pip (gestor de paquetes de Python)
Git

2. Clonar el Repositorio
bashgit clone https://github.com/tu-usuario/tu-repositorio.git
cd tu-repositorio/APIrest
3. Crear Entorno Virtual
Windows:
bashpython -m venv venv
venv\Scripts\activate
Linux/Mac:
bashpython3 -m venv venv
source venv/bin/activate
4. Instalar Dependencias
bashpip install django djangorestframework pymysql django-cors-headers drf-yasg
O si tienes un requirements.txt:
bashpip install -r requirements.txt
5. Configurar Base de Datos MySQL
Crear la base de datos:
sqlCREATE DATABASE apibuses CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
Configurar credenciales en APIrest/settings.py:
pythonDATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': 'apibuses',
        'USER': 'tu_usuario',      # Cambiar
        'PASSWORD': 'tu_password',  # Cambiar
        'HOST': 'localhost',
        'PORT': '3306',
    }
}
6. Ejecutar Migraciones
bashpython manage.py makemigrations
python manage.py migrate
7. Crear Superusuario
bashpython manage.py createsuperuser
Ingresa:

Username: admin
Email: admin@example.com
Password: (tu contraseña segura)

8. Ejecutar Servidor de Desarrollo
bashpython manage.py runserver
El servidor estará disponible en: http://localhost:8000
Documentación de la API


Acceso a la Documentación

Swagger UI: http://localhost:8000/swagger/
ReDoc: http://localhost:8000/redoc/
API Browsable: http://localhost:8000/api/trabajadores/

Autenticación

La API utiliza Token Authentication. Para acceder a los endpoints protegidos:
1. Obtener Token
Endpoint: POST /api/auth/login/
Request:
json{
  "username": "admin",
  "password": "tu_password"
}
Response:
json{
  "token": "9944b09199c62bcf9418ad846dd0e4bbdfc6ee4b",
  "user_id": 1,
  "username": "admin",
  "email": "admin@example.com"
}
2. Usar Token en Requests
Incluir en los headers de todas las peticiones:
Authorization: Token 9944b09199c62bcf9418ad846dd0e4bbdfc6ee4b
3. Cerrar Sesión
Endpoint: POST /api/auth/logout/
Headers:
Authorization: Token tu_token_aqui

Endpoints Disponibles

Autenticación
MétodoEndpointDescripciónPOST/api/auth/login/Login y obtención de tokenPOST/api/auth/logout/Logout (elimina token)
Trabajadores
MétodoEndpointDescripciónGET/api/trabajadores/Listar trabajadoresPOST/api/trabajadores/Crear trabajadorGET/api/trabajadores/{id}/Ver detallePUT/api/trabajadores/{id}/Actualizar completoPATCH/api/trabajadores/{id}/Actualizar parcialDELETE/api/trabajadores/{id}/Eliminar
Filtros disponibles:

?search=Juan - Buscar por nombre/apellido
?activo=true - Filtrar por estado

Roles

MétodoEndpointDescripciónGET/api/roles/Listar rolesPOST/api/roles/Crear rolGET/api/roles/{id}/Ver detallePUT/api/roles/{id}/Actualizar completoPATCH/api/roles/{id}/Actualizar parcialDELETE/api/roles/{id}/Eliminar
Buses
MétodoEndpointDescripciónGET/api/buses/Listar busesPOST/api/buses/Crear busGET/api/buses/{id}/Ver detallePUT/api/buses/{id}/Actualizar completoPATCH/api/buses/{id}/Actualizar parcialDELETE/api/buses/{id}/Eliminar
Estados de Buses
MétodoEndpointDescripciónGET/api/estados-bus/Listar estadosPOST/api/estados-bus/Crear estadoGET/api/estados-bus/{id}/Ver detallePUT/api/estados-bus/{id}/Actualizar completoPATCH/api/estados-bus/{id}/Actualizar parcialDELETE/api/estados-bus/{id}/Eliminar
Asignaciones de Roles
MétodoEndpointDescripciónGET/api/asignaciones-rol/Listar asignacionesPOST/api/asignaciones-rol/Crear asignaciónGET/api/asignaciones-rol/{id}/Ver detallePUT/api/asignaciones-rol/{id}/Actualizar completoPATCH/api/asignaciones-rol/{id}/Actualizar parcialDELETE/api/asignaciones-rol/{id}/Eliminar
Asignaciones de Buses
MétodoEndpointDescripciónGET/api/asignaciones-bus/Listar asignacionesPOST/api/asignaciones-bus/Crear asignaciónGET/api/asignaciones-bus/{id}/Ver detallePUT/api/asignaciones-bus/{id}/Actualizar completoPATCH/api/asignaciones-bus/{id}/Actualizar parcialDELETE/api/asignaciones-bus/{id}/Eliminar

Ejemplos de Uso

Usando cURL
Login:
bashcurl -X POST http://localhost:8000/api/auth/login/ \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}'
Crear Trabajador:
bashcurl -X POST http://localhost:8000/api/trabajadores/ \
  -H "Content-Type: application/json" \
  -H "Authorization: Token tu_token_aqui" \
  -d '{
    "nombre": "Juan",
    "apellido": "Pérez",
    "direccion": "Calle Principal 123",
    "contacto": "+56912345678",
    "edad": 30,
    "activo": true
  }'
Listar Trabajadores:
bashcurl -X GET http://localhost:8000/api/trabajadores/ \
  -H "Authorization: Token tu_token_aqui"
Usando JavaScript (Fetch API)
javascript// Login
const login = async (username, password) => {
  const response = await fetch('http://localhost:8000/api/auth/login/', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password })
  });
  const data = await response.json();
  localStorage.setItem('token', data.token);
  return data;
};

// Obtener trabajadores
const getTrabajadores = async () => {
  const token = localStorage.getItem('token');
  const response = await fetch('http://localhost:8000/api/trabajadores/', {
    headers: { 'Authorization': `Token ${token}` }
  });
  return await response.json();
};

// Crear trabajador
const createTrabajador = async (trabajador) => {
  const token = localStorage.getItem('token');
  const response = await fetch('http://localhost:8000/api/trabajadores/', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Token ${token}`
    },
    body: JSON.stringify(trabajador)
  });
  return await response.json();
};
Usando Python (requests)
pythonimport requests

BASE_URL = "http://localhost:8000"

# Login
def login(username, password):
    response = requests.post(
        f"{BASE_URL}/api/auth/login/",
        json={"username": username, "password": password}
    )
    return response.json()

# Obtener trabajadores
def get_trabajadores(token):
    headers = {"Authorization": f"Token {token}"}
    response = requests.get(f"{BASE_URL}/api/trabajadores/", headers=headers)
    return response.json()

# Crear trabajador
def create_trabajador(token, data):
    headers = {
        "Authorization": f"Token {token}",
        "Content-Type": "application/json"
    }
    response = requests.post(
        f"{BASE_URL}/api/trabajadores/",
        json=data,
        headers=headers
    )
    return response.json()

Sistema de Permisos

Permisos Implementados

IsAdminOrReadOnly: Solo administradores pueden modificar, otros solo leen
CanManageWorkers: Gestión de trabajadores
CanManageBuses: Gestión de buses
CanManageAssignments: Gestión de asignaciones

Reglas por Endpoint

Autenticación: Acceso público
Trabajadores: Requiere autenticación + permisos de gestión
Roles: Solo administradores pueden crear/editar
Buses: Requiere permisos de gestión de buses
Asignaciones: Solo staff puede gestionar

Validaciones Implementadas

Trabajadores

Nombre/apellido: Solo letras, mínimo 2 caracteres
Edad: Entre 18 y 70 años
Contacto: Formato de teléfono válido (8-15 dígitos)
Nombre ≠ Apellido

Roles

Nombre único, solo letras
Nivel de acceso: 1-5
Descripción máximo 500 caracteres

Buses

Patente única, formato válido (ABC-123)
Año: 1990-2025
Capacidad: 10-80 pasajeros
Validación de año no futuro

Estados de Buses

Kilometraje ≥ 0
Estados críticos requieren observaciones (min 10 caracteres)

Asignaciones

No duplicar asignaciones activas
Validar que trabajador/bus/rol estén activos
Validar estado operativo del bus para asignaciones

Testing

Probar con Postman/Thunder Client

Importar la colección desde Swagger: http://localhost:8000/swagger.json
Configurar variable de entorno TOKEN después del login
Ejecutar las peticiones

Probar con API Browsable

Acceder a: http://localhost:8000/api/trabajadores/
Login con tus credenciales
Usar la interfaz visual para probar endpoints

Modelos de Datos

Trabajador
python{
  "id": 1,
  "nombre": "Juan",
  "apellido": "Pérez",
  "direccion": "Calle Principal 123",
  "contacto": "+56912345678",
  "edad": 30,
  "activo": true,
  "fecha_registro": "2025-12-14T10:30:00Z"
}
Rol
python{
  "id": 1,
  "nombre": "Conductor",
  "descripcion": "Conductor de buses urbanos",
  "nivel_acceso": 3,
  "activo": true,
  "fecha_creacion": "2025-12-14T10:30:00Z",
  "cantidad_asignaciones": 5
}
Bus
python{
  "id": 1,
  "patente": "ABC-123",
  "modelo": "Mercedes Benz O500",
  "año": 2020,
  "capacidad": 45,
  "marca": "Mercedes Benz",
  "activo": true,
  "fecha_registro": "2025-12-14T10:30:00Z",
  "estado_actual": {
    "estado": "OPERATIVO",
    "kilometraje": 125000
  }
}

Solución de Problemas

Error de Conexión a MySQL
bash# Verificar que MySQL está corriendo
sudo service mysql status  # Linux
net start MySQL  # Windows

# Verificar credenciales en settings.py
Error de Migraciones
bash# Eliminar migraciones conflictivas
python manage.py migrate --fake busesAPI zero
python manage.py migrate
CORS Errors en Frontend
Verificar en settings.py:
pythonCORS_ALLOW_ALL_ORIGINS = True  # Solo desarrollo

Notas Importantes

La API requiere autenticación para todos los endpoints excepto login
Los tokens no expiran (configuración de desarrollo)
CORS está habilitado para todos los orígenes (solo desarrollo)
Cambiar credenciales de base de datos antes de producción
El SECRET_KEY debe cambiarse en producción

