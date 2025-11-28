from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django.shortcuts import get_object_or_404
from django.db.models import Q
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi

from .models import ChatRoom, Message, DoctorConnection
from .serializers import (
    ChatRoomListSerializer, ChatRoomDetailSerializer,
    MessageSerializer, DoctorConnectionSerializer,
    DoctorConnectionListSerializer, DoctorMinimalSerializer
)
from Authapi.models import Doctor
from .throttles import (
    ChatListThrottle, ChatMessageThrottle,
    ChatConnectionThrottle, ChatSearchThrottle,
    ChatReadThrottle
)


class PatientChatViewSet(viewsets.ViewSet):
    permission_classes = [IsAuthenticated]
    throttle_classes = [ChatListThrottle]

    @swagger_auto_schema(
        operation_summary="List patient's doctor chats",
        tags=["Chat"]
    )
    def list(self, request):
        if request.user.role != "patient":
            return Response({"error": "Only patients allowed"}, status=403)

        # ✅ FIXED: Only fetch chat rooms that actually exist
        chat_rooms = ChatRoom.objects.filter(
            room_type="patient_doctor",
            participants=request.user,
            is_active=True,
            appointment__isnull=False,  # Must have an appointment
            appointment__status="confirmed"  # Appointment must be confirmed
        ).select_related('appointment').prefetch_related("participants")

        print(f"🔍 Patient {request.user.id} has {chat_rooms.count()} chat rooms")
        
        serializer = ChatRoomListSerializer(chat_rooms, many=True, context={"request": request})
        return Response(serializer.data)


class DoctorChatViewSet(viewsets.ViewSet):
    permission_classes = [IsAuthenticated]
    throttle_classes = [ChatListThrottle]

    @swagger_auto_schema(
        operation_summary="List doctor's patient chats",
        tags=["Chat"]
    )
    def list_patients(self, request):
        if request.user.role != "doctor":
            return Response({"error": "Only doctors allowed"}, status=403)

        # ✅ FIXED: Only fetch chat rooms that actually exist
        chat_rooms = ChatRoom.objects.filter(
            room_type="patient_doctor",
            participants=request.user,
            is_active=True,
            appointment__isnull=False,  # Must have an appointment
            appointment__status="confirmed"  # Appointment must be confirmed
        ).select_related('appointment').prefetch_related("participants")

        print(f"🔍 Doctor {request.user.id} has {chat_rooms.count()} patient chat rooms")

        serializer = ChatRoomListSerializer(chat_rooms, many=True, context={"request": request})
        return Response(serializer.data)

    @swagger_auto_schema(
        operation_summary="List doctor's doctor-to-doctor chats",
        tags=["Chat"]
    )
    def list_doctors(self, request):
        if request.user.role != "doctor":
            return Response({"error": "Only doctors allowed"}, status=403)

        chat_rooms = ChatRoom.objects.filter(
            room_type="doctor_doctor",
            participants=request.user,
            is_active=True
        ).prefetch_related("participants")

        serializer = ChatRoomListSerializer(chat_rooms, many=True, context={"request": request})
        return Response(serializer.data)

    @swagger_auto_schema(
        operation_summary="Send a doctor-to-doctor connection request",
        request_body=DoctorConnectionSerializer,
        tags=["Chat"]
    )
    @action(detail=False, methods=["post"], throttle_classes=[ChatConnectionThrottle])
    def send_connection_request(self, request):
        if request.user.role != "doctor":
            return Response({"error": "Only doctors allowed"}, status=403)

        serializer = DoctorConnectionSerializer(
            data=request.data,
            context={"request": request}
        )

        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=201)

        return Response(serializer.errors, status=400)

    @swagger_auto_schema(
        operation_summary="List pending doctor connection requests",
        tags=["Chat"]
    )
    def list_pending_requests(self, request):
        if request.user.role != "doctor":
            return Response({"error": "Only doctors allowed"}, status=403)

        qs = DoctorConnection.objects.filter(
            to_doctor=request.user.doctor_profile,
            status="pending"
        ).select_related("from_doctor__user", "to_doctor__user")

        serializer = DoctorConnectionListSerializer(qs, many=True)
        return Response(serializer.data)

    @swagger_auto_schema(
        operation_summary="Accept a doctor connection request",
        tags=["Chat"]
    )
    def accept_connection(self, request, pk):
        if request.user.role != "doctor":
            return Response({"error": "Only doctors allowed"}, status=403)

        connection = get_object_or_404(
            DoctorConnection,
            pk=pk,
            to_doctor=request.user.doctor_profile,
            status="pending"
        )

        connection.status = "accepted"

        chat_room = ChatRoom.objects.create(
            room_type="doctor_doctor",
            is_active=True
        )
        chat_room.participants.add(
            connection.from_doctor.user,
            connection.to_doctor.user
        )

        connection.chat_room = chat_room
        connection.save()

        return Response(DoctorConnectionSerializer(connection).data)

    @swagger_auto_schema(
        operation_summary="Reject a doctor connection request",
        tags=["Chat"]
    )
    def reject_connection(self, request, pk):
        if request.user.role != "doctor":
            return Response({"error": "Only doctors allowed"}, status=403)

        connection = get_object_or_404(
            DoctorConnection,
            pk=pk,
            to_doctor=request.user.doctor_profile,
            status="pending"
        )

        connection.status = "rejected"
        connection.save()

        return Response({"message": "Connection rejected"})

    @swagger_auto_schema(
        operation_summary="Search doctors",
        manual_parameters=[
            openapi.Parameter("q", openapi.IN_QUERY, type=openapi.TYPE_STRING, description="Search keyword")
        ],
        tags=["Chat"]
    )
    @action(detail=False, methods=["get"], throttle_classes=[ChatSearchThrottle])
    def search_doctors(self, request):
        if request.user.role != "doctor":
            return Response({"error": "Only doctors allowed"}, status=403)

        q = request.query_params.get("q", "").strip()
        if not q:
            return Response({"error": "Query param 'q' is required"}, status=400)

        doctors = Doctor.objects.filter(
            Q(first_name__icontains=q) |
            Q(last_name__icontains=q) |
            Q(specialization__icontains=q)
        ).exclude(user=request.user).select_related("user")[:20]

        return Response(DoctorMinimalSerializer(doctors, many=True).data)


class ChatRoomViewSet(viewsets.ViewSet):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(tags=["Chat"])
    def retrieve(self, request, pk):
        try:
            chat_room = ChatRoom.objects.prefetch_related(
                "participants"
            ).select_related("appointment").get(pk=pk)
        except ChatRoom.DoesNotExist:
            print(f"❌ Chat room {pk} not found")
            return Response(
                {"error": "Chat room not found", "detail": "This chat may have been deleted"},
                status=404
            )

        if not chat_room.participants.filter(id=request.user.id).exists():
            return Response({"error": "Not a participant"}, status=403)

        if not chat_room.is_active:
            return Response(
                {"error": "Chat inactive", "detail": "This chat has been deactivated"},
                status=403
            )

        serializer = ChatRoomDetailSerializer(chat_room, context={"request": request})
        return Response(serializer.data)

    @swagger_auto_schema(tags=["Chat"])
    @action(detail=True, methods=["post"], throttle_classes=[ChatMessageThrottle])
    def send_message(self, request, pk):
        chat_room = get_object_or_404(ChatRoom, pk=pk)

        if not chat_room.participants.filter(id=request.user.id).exists():
            return Response({"error": "Not a participant"}, status=403)

        if not chat_room.is_active:
            return Response({"error": "Chat inactive"}, status=403)

        content = request.data.get("content", "").strip()
        if not content:
            return Response({"error": "Message content required"}, status=400)

        message = Message.objects.create(
            room=chat_room,
            sender=request.user,
            content=content
        )

        return Response(MessageSerializer(message).data, status=201)

    @swagger_auto_schema(tags=["Chat"])
    @action(detail=True, methods=["post"], throttle_classes=[ChatReadThrottle])
    def mark_as_read(self, request, pk):
        chat_room = get_object_or_404(ChatRoom, pk=pk)

        if not chat_room.participants.filter(id=request.user.id).exists():
            return Response({"error": "Not a participant"}, status=403)

        Message.objects.filter(
            room=chat_room,
            is_read=False
        ).exclude(sender=request.user).update(is_read=True)

        return Response({"message": "Messages marked as read"})