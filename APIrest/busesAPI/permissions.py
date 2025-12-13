from rest_framework import permissions


class IsAdminOrReadOnly(permissions.BasePermission):
    """
    Permiso personalizado: Solo admin puede crear/editar/eliminar
    Otros usuarios autenticados solo pueden leer
    """
    
    def has_permission(self, request, view):
        # Permitir lectura a usuarios autenticados
        if request.method in permissions.SAFE_METHODS:
            return request.user and request.user.is_authenticated
        
        # Solo admin puede modificar
        return request.user and request.user.is_staff


class IsOwnerOrAdmin(permissions.BasePermission):
    """
    Permiso: Solo el dueño del objeto o admin puede editar/eliminar
    """
    
    def has_object_permission(self, request, view, obj):
        # Lectura permitida para todos los autenticados
        if request.method in permissions.SAFE_METHODS:
            return True
        
        # Admin puede hacer todo
        if request.user.is_staff:
            return True
        
        # Si el objeto tiene un campo 'user', verificar propiedad
        if hasattr(obj, 'user'):
            return obj.user == request.user
        
        return False


class CanManageWorkers(permissions.BasePermission):
    """
    Permiso: Solo usuarios con rol de supervisor o admin pueden gestionar trabajadores
    """
    
    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        
        # Admin siempre puede
        if request.user.is_staff or request.user.is_superuser:
            return True
        
        # Lectura para todos los autenticados
        if request.method in permissions.SAFE_METHODS:
            return True
        
        # Para crear/editar/eliminar, verificar si es supervisor
        # (Esto requeriría una relación entre User y Rol en producción)
        return False


class CanManageBuses(permissions.BasePermission):
    """
    Permiso: Gestión de buses solo para personal autorizado
    """
    
    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        
        # Admin siempre puede
        if request.user.is_staff or request.user.is_superuser:
            return True
        
        # Lectura para todos
        if request.method in permissions.SAFE_METHODS:
            return True
        
        return False


class CanManageAssignments(permissions.BasePermission):
    """
    Permiso: Gestión de asignaciones
    """
    
    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        
        # Solo staff puede gestionar asignaciones
        if request.method in permissions.SAFE_METHODS:
            return True
        
        return request.user.is_staff or request.user.is_superuser