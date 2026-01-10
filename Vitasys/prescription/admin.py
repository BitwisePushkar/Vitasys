from django.contrib import admin
from .models import Prescription, Medication, LabTest


class MedicationInline(admin.TabularInline):
    model = Medication
    extra = 1
    fields = ['medicine_name', 'dosage', 'frequency', 'duration', 'duration_unit', 'instructions']


class LabTestInline(admin.TabularInline):
    model = LabTest
    extra = 1
    fields = ['test_name', 'instructions']


@admin.register(Prescription)
class PrescriptionAdmin(admin.ModelAdmin):
    list_display = ['id', 'patient_name', 'doctor_name', 'diagnosis', 'created_at']
    list_filter = ['created_at', 'doctor', 'follow_up_date']
    search_fields = [
        'patient__first_name',
        'patient__last_name',
        'doctor__first_name',
        'doctor__last_name',
        'diagnosis',
        'chief_complaint'
    ]
    readonly_fields = ['created_at', 'updated_at']
    inlines = [MedicationInline, LabTestInline]
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('doctor', 'patient', 'appointment')
        }),
        ('Medical Details', {
            'fields': ('chief_complaint', 'diagnosis')
        }),
        ('Vital Signs', {
            'fields': ('blood_pressure', 'temperature', 'pulse_rate', 'weight'),
            'classes': ('collapse',)
        }),
        ('Additional Information', {
            'fields': ('additional_notes', 'follow_up_date')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        })
    )
    
    def patient_name(self, obj):
        return obj.patient.get_full_name()
    patient_name.short_description = 'Patient'
    patient_name.admin_order_field = 'patient__first_name'
    
    def doctor_name(self, obj):
        return f"Dr. {obj.doctor.get_full_name()}"
    doctor_name.short_description = 'Doctor'
    doctor_name.admin_order_field = 'doctor__first_name'


@admin.register(Medication)
class MedicationAdmin(admin.ModelAdmin):
    list_display = ['id', 'prescription_patient', 'medicine_name', 'dosage', 'frequency', 'duration', 'duration_unit']
    list_filter = ['frequency', 'duration_unit', 'created_at']
    search_fields = ['medicine_name', 'prescription__patient__first_name', 'prescription__patient__last_name']
    readonly_fields = ['created_at']
    
    def prescription_patient(self, obj):
        return obj.prescription.patient.get_full_name()
    prescription_patient.short_description = 'Patient'


@admin.register(LabTest)
class LabTestAdmin(admin.ModelAdmin):
    list_display = ['id', 'prescription_patient', 'test_name', 'created_at']
    list_filter = ['created_at']
    search_fields = ['test_name', 'prescription__patient__first_name', 'prescription__patient__last_name']
    readonly_fields = ['created_at']
    
    def prescription_patient(self, obj):
        return obj.prescription.patient.get_full_name()
    prescription_patient.short_description = 'Patient'