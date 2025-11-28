from rest_framework import serializers
from django.contrib.auth import get_user_model
from .models import ChatRoom, Message, DoctorConnection
from Authapi.models import Doctor, Patient
from django.db import models
User = get_user_model()

class UserBasicSerializer(serializers.ModelSerializer):
    full_name = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ["id", "username", "email", "role", "full_name"]

    def get_full_name(self, obj):
        if obj.role == "doctor":
            return f"Dr. {obj.doctor_profile.get_full_name()}"
        if obj.role == "patient":
            return obj.patient_profile.get_full_name()
        return obj.username

class DoctorMinimalSerializer(serializers.ModelSerializer):
    full_name = serializers.SerializerMethodField()
    user_id = serializers.IntegerField(source="user.id")

    class Meta:
        model = Doctor
        fields = ["id", "user_id", "full_name", "specialization"]

    def get_full_name(self, obj):
        return f"Dr. {obj.get_full_name()}"


class PatientMinimalSerializer(serializers.ModelSerializer):
    full_name = serializers.SerializerMethodField()
    user_id = serializers.IntegerField(source="user.id")

    class Meta:
        model = Patient
        fields = ["id", "user_id", "full_name", "city"]

    def get_full_name(self, obj):
        return obj.get_full_name()

class MessageSerializer(serializers.ModelSerializer):
    sender = UserBasicSerializer(read_only=True)

    class Meta:
        model = Message
        fields = [
            "id", "room", "sender",
            "content", "timestamp", "is_read"
        ]
        read_only_fields = ["id", "timestamp", "is_read", "room"]


class MessageCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Message
        fields = ["room", "content"]

class ChatRoomListSerializer(serializers.ModelSerializer):
    participants = UserBasicSerializer(many=True, read_only=True)
    last_message = serializers.SerializerMethodField()
    unread_count = serializers.SerializerMethodField()
    other_participant = serializers.SerializerMethodField()

    class Meta:
        model = ChatRoom
        fields = [
            "id", "room_type", "name", "is_active",
            "participants", "last_message",
            "unread_count", "other_participant",
            "created_at", "updated_at"
        ]

    def get_last_message(self, obj):
        msg = obj.messages.order_by("-timestamp").first()
        if not msg:
            return None

        return {
            "id": msg.id,
            "content": msg.content[:100],
            "timestamp": msg.timestamp,
            "sender": msg.sender.username
        }

    def get_unread_count(self, obj):
        request = self.context.get("request")
        if not request:
            return 0

        return obj.messages.filter(
            is_read=False
        ).exclude(sender=request.user).count()

    def get_other_participant(self, obj):
        request = self.context.get("request")
        if not request:
            return None

        other = obj.participants.exclude(id=request.user.id).first()
        if not other:
            return None

        return UserBasicSerializer(other).data

class ChatRoomDetailSerializer(serializers.ModelSerializer):
    participants = UserBasicSerializer(many=True, read_only=True)
    messages = serializers.SerializerMethodField()
    appointment_info = serializers.SerializerMethodField()

    class Meta:
        model = ChatRoom
        fields = [
            "id", "room_type", "name", "is_active",
            "participants", "messages", "appointment_info"
        ]

    def get_messages(self, obj):
        msgs = obj.messages.order_by("-timestamp")[:50]
        return MessageSerializer(msgs, many=True).data

    def get_appointment_info(self, obj):
        appt = obj.appointment
        if not appt:
            return None

        return {
            "id": appt.id,
            "date": appt.appointment_date,
            "time": appt.appointment_time,
            "status": appt.status
        }

class DoctorConnectionSerializer(serializers.ModelSerializer):
    from_doctor = DoctorMinimalSerializer(read_only=True)
    to_doctor = DoctorMinimalSerializer(read_only=True)
    to_doctor_id = serializers.IntegerField(write_only=True)

    class Meta:
        model = DoctorConnection
        fields = [
            "id", "from_doctor", "to_doctor", "to_doctor_id",
            "status", "chat_room", "created_at", "updated_at"
        ]
        read_only_fields = ["id", "status", "chat_room", "created_at", "updated_at"]

    def create(self, validated_data):
        to_doctor_id = validated_data.pop("to_doctor_id")
        
        try:
            to_doc = Doctor.objects.get(id=to_doctor_id)
        except Doctor.DoesNotExist:
            raise serializers.ValidationError("Doctor not found")
        
        from_doc = self.context["request"].user.doctor_profile
        
        if from_doc.id == to_doc.id:
            raise serializers.ValidationError("Cannot connect to yourself")
        
        if DoctorConnection.objects.filter(
            models.Q(from_doctor=from_doc, to_doctor=to_doc) |
            models.Q(from_doctor=to_doc, to_doctor=from_doc)
        ).exists():
            raise serializers.ValidationError("Connection already exists")
        
        return DoctorConnection.objects.create(
            from_doctor=from_doc,
            to_doctor=to_doc,
            status="pending"
        )


class DoctorConnectionListSerializer(serializers.ModelSerializer):
    from_doctor = DoctorMinimalSerializer(read_only=True)
    to_doctor = DoctorMinimalSerializer(read_only=True)

    class Meta:
        model = DoctorConnection
        fields = ["id", "from_doctor", "to_doctor", "status", "created_at"]
