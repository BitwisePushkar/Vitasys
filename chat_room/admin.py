from django.contrib import admin
from .models import ChatRoom, Message, DoctorConnection

@admin.register(ChatRoom)
class ChatRoomAdmin(admin.ModelAdmin):
    list_display = ['id', 'room_type', 'name', 'is_active', 'created_at']
    list_filter = ['room_type', 'is_active', 'created_at']
    search_fields = ['name', 'disease_name']
    filter_horizontal = ['participants']
    readonly_fields = ['created_at', 'updated_at']


@admin.register(Message)
class MessageAdmin(admin.ModelAdmin):
    list_display = ['id', 'room', 'sender', 'content_preview', 'timestamp', 'is_read']
    list_filter = ['is_read', 'timestamp']
    search_fields = ['content', 'sender__username']
    readonly_fields = ['timestamp']
    
    def content_preview(self, obj):
        return obj.content[:50] + '...' if len(obj.content) > 50 else obj.content
    content_preview.short_description = 'Message'


@admin.register(DoctorConnection)
class DoctorConnectionAdmin(admin.ModelAdmin):
    list_display = ['id', 'from_doctor', 'to_doctor', 'status', 'created_at']
    list_filter = ['status', 'created_at']
    search_fields = ['from_doctor__first_name', 'to_doctor__first_name']
    readonly_fields = ['created_at', 'updated_at']