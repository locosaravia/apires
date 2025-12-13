from django.db import models
from django.core.validators import MinValueValidator, MaxValueValidator, RegexValidator
from django.core.exceptions import ValidationError
from django.utils import timezone


class Trabajador(models.Model):
    nombre = models.CharField(
        max_length=100,
        validators=[RegexValidator(r'^[a-zA-ZáéíóúÁÉÍÓÚñÑ\s]+$', 'Solo se permiten letras')]
    )
    apellido = models.CharField(
        max_length=100,
        validators=[RegexValidator(r'^[a-zA-ZáéíóúÁÉÍÓÚñÑ\s]+$', 'Solo se permiten letras')]
    )
    direccion = models.CharField(max_length=255)
    contacto = models.CharField(
        max_length=50,
        validators=[RegexValidator(r'^\+?[0-9\s\-]+$', 'Formato de contacto inválido')]
    )
    edad = models.PositiveIntegerField(
        validators=[MinValueValidator(18, 'Debe ser mayor de 18 años'), 
                   MaxValueValidator(70, 'Edad máxima 70 años')]
    )
    activo = models.BooleanField(default=True)
    fecha_registro = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "Trabajador"
        verbose_name_plural = "Trabajadores"
        ordering = ['apellido', 'nombre']
        constraints = [
            models.CheckConstraint(
                check=models.Q(edad__gte=18) & models.Q(edad__lte=70),
                name='edad_valida'
            )
        ]

    def clean(self):
        if self.edad and self.edad < 18:
            raise ValidationError('Trabajador debe ser mayor de 18 años')
        if self.nombre and self.apellido:
            if self.nombre.lower() == self.apellido.lower():
                raise ValidationError('El nombre y apellido no pueden ser iguales')

    def __str__(self):
        return f"{self.nombre} {self.apellido}"

    def get_asignaciones_activas(self):
        """Retorna las asignaciones activas del trabajador"""
        return {
            'roles': self.asignaciones_rol.filter(activo=True),
            'buses': self.asignaciones_bus.filter(activo=True)
        }


class Rol(models.Model):
    nombre = models.CharField(
        max_length=100,
        unique=True,
        validators=[RegexValidator(r'^[a-zA-ZáéíóúÁÉÍÓÚñÑ\s]+$', 'Solo se permiten letras')]
    )
    descripcion = models.TextField(blank=True, null=True)
    nivel_acceso = models.PositiveIntegerField(
        default=1,
        validators=[MinValueValidator(1), MaxValueValidator(5)]
    )
    activo = models.BooleanField(default=True)
    fecha_creacion = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "Rol"
        verbose_name_plural = "Roles"
        ordering = ['nombre']

    def __str__(self):
        return self.nombre

    def cantidad_asignaciones_activas(self):
        """Retorna cantidad de trabajadores con este rol activo"""
        return self.asignaciones.filter(activo=True).count()


class Bus(models.Model):
    patente = models.CharField(
        max_length=20, 
        unique=True,
        validators=[RegexValidator(r'^[A-Z0-9\-]+$', 'Formato de patente inválido')]
    )
    modelo = models.CharField(max_length=100)
    año = models.PositiveIntegerField(
        validators=[MinValueValidator(1990, 'Año mínimo 1990'), 
                   MaxValueValidator(2025, 'Año máximo 2025')]
    )
    capacidad = models.PositiveIntegerField(
        validators=[MinValueValidator(10, 'Capacidad mínima 10 pasajeros'),
                   MaxValueValidator(80, 'Capacidad máxima 80 pasajeros')]
    )
    marca = models.CharField(max_length=100, default='Sin especificar')
    activo = models.BooleanField(default=True)
    fecha_registro = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "Bus"
        verbose_name_plural = "Buses"
        ordering = ['patente']

    def clean(self):
        if self.año > timezone.now().year:
            raise ValidationError('El año no puede ser futuro')

    def __str__(self):
        return f"{self.patente} - {self.modelo}"

    def get_estado_actual(self):
        """Retorna el estado actual del bus"""
        try:
            return self.estado
        except EstadoBus.DoesNotExist:
            return None


class EstadoBus(models.Model):
    ESTADOS_CHOICES = [
        ('OPERATIVO', 'Operativo'),
        ('MANTENIMIENTO', 'En Mantenimiento'),
        ('REPARACION', 'En Reparación'),
        ('FUERA_SERVICIO', 'Fuera de Servicio'),
        ('RESERVADO', 'Reservado'),
    ]

    # ForeignKey REAL al modelo Bus
    bus = models.OneToOneField(
        Bus,
        on_delete=models.CASCADE,
        related_name='estado',
        verbose_name='Bus'
    )
    estado = models.CharField(
        max_length=50, 
        choices=ESTADOS_CHOICES, 
        default='OPERATIVO'
    )
    observaciones = models.TextField(blank=True, null=True)
    fecha_cambio = models.DateTimeField(auto_now=True)
    kilometraje = models.PositiveIntegerField(
        default=0,
        validators=[MinValueValidator(0)]
    )

    class Meta:
        verbose_name = "Estado de Bus"
        verbose_name_plural = "Estados de Buses"
        ordering = ['-fecha_cambio']

    def clean(self):
        if self.kilometraje < 0:
            raise ValidationError('El kilometraje no puede ser negativo')
        
        # Validar que estados críticos tengan observaciones
        if self.estado in ['MANTENIMIENTO', 'REPARACION', 'FUERA_SERVICIO']:
            if not self.observaciones or len(self.observaciones.strip()) < 10:
                raise ValidationError(
                    f'El estado "{self.get_estado_display()}" requiere observaciones detalladas'
                )

    def __str__(self):
        return f"{self.bus.patente} - {self.get_estado_display()}"


class AsignacionRol(models.Model):
    # ForeignKeys REALES
    trabajador = models.ForeignKey(
        Trabajador,
        on_delete=models.CASCADE,
        related_name='asignaciones_rol',
        verbose_name='Trabajador'
    )
    rol = models.ForeignKey(
        Rol,
        on_delete=models.CASCADE,
        related_name='asignaciones',
        verbose_name='Rol'
    )
    fecha_asignacion = models.DateField(auto_now_add=True)
    fecha_finalizacion = models.DateField(blank=True, null=True)
    activo = models.BooleanField(default=True)
    notas = models.TextField(blank=True, null=True)

    class Meta:
        verbose_name = "Asignación de Rol"
        verbose_name_plural = "Asignaciones de Roles"
        ordering = ['-fecha_asignacion']
        constraints = [
            models.UniqueConstraint(
                fields=['trabajador', 'rol'],
                condition=models.Q(activo=True),
                name='unique_active_rol_asignacion'
            )
        ]

    def clean(self):
        if self.fecha_finalizacion and self.fecha_asignacion:
            if self.fecha_finalizacion < self.fecha_asignacion:
                raise ValidationError('La fecha de finalización no puede ser anterior a la asignación')
        
        # Validar que el trabajador esté activo
        if self.trabajador and not self.trabajador.activo:
            raise ValidationError('No se puede asignar un rol a un trabajador inactivo')
        
        # Validar que el rol esté activo
        if self.rol and not self.rol.activo:
            raise ValidationError('No se puede asignar un rol inactivo')

    def __str__(self):
        return f"{self.trabajador} → {self.rol}"

    def finalizar_asignacion(self):
        """Finaliza la asignación estableciendo fecha fin y desactivando"""
        self.fecha_finalizacion = timezone.now().date()
        self.activo = False
        self.save()


class AsignacionBus(models.Model):
    TURNO_CHOICES = [
        ('MAÑANA', 'Mañana'),
        ('TARDE', 'Tarde'),
        ('NOCHE', 'Noche'),
    ]

    # ForeignKeys REALES
    trabajador = models.ForeignKey(
        Trabajador,
        on_delete=models.CASCADE,
        related_name='asignaciones_bus',
        verbose_name='Trabajador'
    )
    bus = models.ForeignKey(
        Bus,
        on_delete=models.CASCADE,
        related_name='asignaciones',
        verbose_name='Bus'
    )
    fecha_asignacion = models.DateField(auto_now_add=True)
    fecha_finalizacion = models.DateField(blank=True, null=True)
    turno = models.CharField(
        max_length=20,
        choices=TURNO_CHOICES,
        default='MAÑANA'
    )
    activo = models.BooleanField(default=True)
    notas = models.TextField(blank=True, null=True)

    class Meta:
        verbose_name = "Asignación de Bus"
        verbose_name_plural = "Asignaciones de Buses"
        ordering = ['-fecha_asignacion']
        constraints = [
            models.UniqueConstraint(
                fields=['trabajador', 'bus', 'turno'],
                condition=models.Q(activo=True),
                name='unique_active_bus_asignacion'
            )
        ]

    def clean(self):
        if self.fecha_finalizacion and self.fecha_asignacion:
            if self.fecha_finalizacion < self.fecha_asignacion:
                raise ValidationError('La fecha de finalización no puede ser anterior a la asignación')
        
        # Validar que el trabajador esté activo
        if self.trabajador and not self.trabajador.activo:
            raise ValidationError('No se puede asignar un bus a un trabajador inactivo')
        
        # Validar que el bus esté activo
        if self.bus and not self.bus.activo:
            raise ValidationError('No se puede asignar un bus inactivo')
        
        # Validar que el bus esté operativo
        estado_bus = self.bus.get_estado_actual()
        if estado_bus and estado_bus.estado != 'OPERATIVO':
            raise ValidationError(
                f'No se puede asignar el bus {self.bus.patente} porque está en estado: {estado_bus.get_estado_display()}'
            )

    def __str__(self):
        return f"{self.trabajador} → {self.bus.patente} ({self.get_turno_display()})"

    def finalizar_asignacion(self):
        """Finaliza la asignación estableciendo fecha fin y desactivando"""
        self.fecha_finalizacion = timezone.now().date()
        self.activo = False
        self.save()