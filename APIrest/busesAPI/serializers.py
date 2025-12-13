from rest_framework import serializers
from .models import Trabajador, Rol, Bus, EstadoBus, AsignacionRol, AsignacionBus
from django.core.exceptions import ValidationError
from datetime import date
import re


class TrabajadorSerializer(serializers.ModelSerializer):
    """Serializer para el modelo Trabajador con validaciones"""
    
    class Meta:
        model = Trabajador
        fields = ['id', 'nombre', 'apellido', 'direccion', 'contacto', 'edad', 'activo', 'fecha_registro']
        read_only_fields = ['id', 'fecha_registro']
    
    def validate_nombre(self, value):
        """Validar nombre"""
        if not re.match(r'^[a-zA-ZáéíóúÁÉÍÓÚñÑ\s]+$', value):
            raise serializers.ValidationError('El nombre solo puede contener letras')
        if len(value) < 2:
            raise serializers.ValidationError('El nombre debe tener al menos 2 caracteres')
        return value.strip().title()
    
    def validate_apellido(self, value):
        """Validar apellido"""
        if not re.match(r'^[a-zA-ZáéíóúÁÉÍÓÚñÑ\s]+$', value):
            raise serializers.ValidationError('El apellido solo puede contener letras')
        if len(value) < 2:
            raise serializers.ValidationError('El apellido debe tener al menos 2 caracteres')
        return value.strip().title()
    
    def validate_contacto(self, value):
        """Validar contacto"""
        contacto_limpio = re.sub(r'[\s\-]', '', value)
        if not re.match(r'^\+?[0-9]{8,15}$', contacto_limpio):
            raise serializers.ValidationError('Formato de teléfono inválido. Debe contener entre 8 y 15 dígitos')
        return value
    
    def validate_edad(self, value):
        """Validar edad"""
        if value < 18:
            raise serializers.ValidationError('El trabajador debe ser mayor de 18 años')
        if value > 70:
            raise serializers.ValidationError('La edad máxima permitida es 70 años')
        return value
    
    def validate(self, data):
        """Validaciones a nivel de objeto"""
        nombre = data.get('nombre')
        apellido = data.get('apellido')
        
        if nombre and apellido:
            if nombre.lower() == apellido.lower():
                raise serializers.ValidationError('El nombre y apellido no pueden ser iguales')
        
        return data


class RolSerializer(serializers.ModelSerializer):
    """Serializer para el modelo Rol con validaciones"""
    cantidad_asignaciones = serializers.SerializerMethodField()
    
    class Meta:
        model = Rol
        fields = ['id', 'nombre', 'descripcion', 'nivel_acceso', 'activo', 'fecha_creacion', 'cantidad_asignaciones']
        read_only_fields = ['id', 'fecha_creacion']
    
    def get_cantidad_asignaciones(self, obj):
        """Obtener cantidad de asignaciones activas"""
        return obj.asignaciones.filter(activo=True).count()
    
    def validate_nombre(self, value):
        """Validar nombre"""
        if not re.match(r'^[a-zA-ZáéíóúÁÉÍÓÚñÑ\s]+$', value):
            raise serializers.ValidationError('El nombre del rol solo puede contener letras')
        if len(value) < 3:
            raise serializers.ValidationError('El nombre debe tener al menos 3 caracteres')
        return value.strip().title()
    
    def validate_nivel_acceso(self, value):
        """Validar nivel de acceso"""
        if value < 1 or value > 5:
            raise serializers.ValidationError('El nivel de acceso debe estar entre 1 y 5')
        return value
    
    def validate_descripcion(self, value):
        """Validar descripción"""
        if value and len(value) > 500:
            raise serializers.ValidationError('La descripción no puede exceder 500 caracteres')
        return value


class BusSerializer(serializers.ModelSerializer):
    """Serializer para el modelo Bus con validaciones"""
    estado_actual = serializers.SerializerMethodField()
    
    class Meta:
        model = Bus
        fields = ['id', 'patente', 'modelo', 'año', 'capacidad', 'marca', 'activo', 'fecha_registro', 'estado_actual']
        read_only_fields = ['id', 'fecha_registro']
    
    def get_estado_actual(self, obj):
        """Obtener estado actual del bus"""
        try:
            estado = obj.estado
            return {
                'estado': estado.estado,
                'estado_display': estado.get_estado_display(),
                'kilometraje': estado.kilometraje
            }
        except EstadoBus.DoesNotExist:
            return None
    
    def validate_patente(self, value):
        """Validar patente"""
        value = value.upper().strip()
        if not re.match(r'^[A-Z0-9]{2,4}[-]?[A-Z0-9]{2,4}$', value):
            raise serializers.ValidationError('Formato de patente inválido. Ej: ABC-123 o ABCD-12')
        return value
    
    def validate_año(self, value):
        """Validar año"""
        año_actual = date.today().year
        if value < 1990:
            raise serializers.ValidationError('El año no puede ser anterior a 1990')
        if value > año_actual:
            raise serializers.ValidationError(f'El año no puede ser posterior a {año_actual}')
        return value
    
    def validate_capacidad(self, value):
        """Validar capacidad"""
        if value < 10:
            raise serializers.ValidationError('La capacidad mínima es 10 pasajeros')
        if value > 80:
            raise serializers.ValidationError('La capacidad máxima es 80 pasajeros')
        return value
    
    def validate(self, data):
        """Validaciones a nivel de objeto"""
        año = data.get('año')
        capacidad = data.get('capacidad')
        
        if año and capacidad:
            if año < 2000 and capacidad > 60:
                raise serializers.ValidationError(
                    'Buses anteriores al 2000 no suelen tener capacidad mayor a 60 pasajeros'
                )
        
        return data


class EstadoBusSerializer(serializers.ModelSerializer):
    """Serializer para el modelo EstadoBus con validaciones"""
    bus_patente = serializers.CharField(source='bus.patente', read_only=True)
    bus_modelo = serializers.CharField(source='bus.modelo', read_only=True)
    estado_display = serializers.CharField(source='get_estado_display', read_only=True)
    
    class Meta:
        model = EstadoBus
        fields = ['id', 'bus', 'bus_patente', 'bus_modelo', 'estado', 'estado_display', 
                  'observaciones', 'kilometraje', 'fecha_cambio']
        read_only_fields = ['id', 'fecha_cambio']
    
    def validate_kilometraje(self, value):
        """Validar kilometraje"""
        if value < 0:
            raise serializers.ValidationError('El kilometraje no puede ser negativo')
        if value > 2000000:
            raise serializers.ValidationError('El kilometraje parece excesivo. Verifique el valor')
        return value
    
    def validate(self, data):
        """Validaciones a nivel de objeto"""
        estado = data.get('estado')
        observaciones = data.get('observaciones')
        
        if estado in ['MANTENIMIENTO', 'REPARACION', 'FUERA_SERVICIO']:
            if not observaciones or len(observaciones.strip()) < 10:
                raise serializers.ValidationError({
                    'observaciones': f'Para el estado "{dict(EstadoBus.ESTADOS_CHOICES).get(estado)}" debe proporcionar observaciones detalladas (mínimo 10 caracteres)'
                })
        
        return data


class AsignacionRolSerializer(serializers.ModelSerializer):
    """Serializer para el modelo AsignacionRol con validaciones"""
    trabajador_nombre = serializers.CharField(source='trabajador.nombre', read_only=True)
    trabajador_apellido = serializers.CharField(source='trabajador.apellido', read_only=True)
    rol_nombre = serializers.CharField(source='rol.nombre', read_only=True)
    
    class Meta:
        model = AsignacionRol
        fields = ['id', 'trabajador', 'trabajador_nombre', 'trabajador_apellido', 
                  'rol', 'rol_nombre', 'fecha_asignacion', 'fecha_finalizacion', 
                  'activo', 'notas']
        read_only_fields = ['id', 'fecha_asignacion']
    
    def validate_fecha_finalizacion(self, value):
        """Validar fecha de finalización"""
        if value and value < date.today():
            raise serializers.ValidationError('La fecha de finalización no puede ser en el pasado')
        return value
    
    def validate(self, data):
        """Validaciones a nivel de objeto"""
        trabajador = data.get('trabajador')
        rol = data.get('rol')
        activo = data.get('activo', True)
        
        # Validar que el trabajador esté activo
        if trabajador and not trabajador.activo:
            raise serializers.ValidationError({
                'trabajador': 'No se puede asignar un rol a un trabajador inactivo'
            })
        
        # Validar que el rol esté activo
        if rol and not rol.activo:
            raise serializers.ValidationError({
                'rol': 'No se puede asignar un rol inactivo'
            })
        
        # Validar que no exista otra asignación activa igual
        if trabajador and rol and activo:
            existe = AsignacionRol.objects.filter(
                trabajador=trabajador,
                rol=rol,
                activo=True
            )
            
            # Si estamos editando, excluir la instancia actual
            if self.instance:
                existe = existe.exclude(pk=self.instance.pk)
            
            if existe.exists():
                raise serializers.ValidationError(
                    f'Ya existe una asignación activa del rol "{rol.nombre}" para {trabajador}'
                )
        
        return data


class AsignacionBusSerializer(serializers.ModelSerializer):
    """Serializer para el modelo AsignacionBus con validaciones"""
    trabajador_nombre = serializers.CharField(source='trabajador.nombre', read_only=True)
    trabajador_apellido = serializers.CharField(source='trabajador.apellido', read_only=True)
    bus_patente = serializers.CharField(source='bus.patente', read_only=True)
    bus_modelo = serializers.CharField(source='bus.modelo', read_only=True)
    turno_display = serializers.CharField(source='get_turno_display', read_only=True)
    
    class Meta:
        model = AsignacionBus
        fields = ['id', 'trabajador', 'trabajador_nombre', 'trabajador_apellido',
                  'bus', 'bus_patente', 'bus_modelo', 'fecha_asignacion', 
                  'fecha_finalizacion', 'turno', 'turno_display', 'activo', 'notas']
        read_only_fields = ['id', 'fecha_asignacion']
    
    def validate_fecha_finalizacion(self, value):
        """Validar fecha de finalización"""
        if value and value < date.today():
            raise serializers.ValidationError('La fecha de finalización no puede ser en el pasado')
        return value
    
    def validate(self, data):
        """Validaciones a nivel de objeto"""
        trabajador = data.get('trabajador')
        bus = data.get('bus')
        turno = data.get('turno')
        activo = data.get('activo', True)
        
        # Validar que el trabajador esté activo
        if trabajador and not trabajador.activo:
            raise serializers.ValidationError({
                'trabajador': 'No se puede asignar un bus a un trabajador inactivo'
            })
        
        # Validar que el bus esté activo
        if bus and not bus.activo:
            raise serializers.ValidationError({
                'bus': 'No se puede asignar un bus inactivo'
            })
        
        # Validar que no exista otra asignación activa igual
        if trabajador and bus and turno and activo:
            existe = AsignacionBus.objects.filter(
                trabajador=trabajador,
                bus=bus,
                turno=turno,
                activo=True
            )
            
            # Si estamos editando, excluir la instancia actual
            if self.instance:
                existe = existe.exclude(pk=self.instance.pk)
            
            if existe.exists():
                raise serializers.ValidationError(
                    f'Ya existe una asignación activa del bus "{bus.patente}" para {trabajador} en el turno {turno}'
                )
        
        return data