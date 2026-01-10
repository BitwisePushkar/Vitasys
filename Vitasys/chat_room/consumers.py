from channels.generic.websocket import AsyncWebsocketConsumer
import json
from channels.db import database_sync_to_async
from django.contrib.auth import get_user_model
from .models import ChatRoom, Message
from django.utils import timezone
from urllib.parse import parse_qs
User = get_user_model()

class ChatConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        try:
            self.room_id = int(self.scope['url_route']['kwargs']['room_id'])
        except:
            await self.close(code=4004)
            return

        self.room_group_name = f'chat_{self.room_id}'

        query_string = self.scope.get('query_string', b'').decode()
        query_params = parse_qs(query_string)
        token = query_params.get('token', [None])[0]

        if token:
            self.user = await self.get_user_from_token(token)
        else:
            self.user = self.scope.get('user')

        if not self.user or not self.user.is_authenticated:
            await self.close(code=4001)
            return

        room_data = await self.get_room_data()
        if not room_data:
            await self.close(code=4004)
            return

        if not room_data['is_participant']:
            await self.close(code=4003)
            return

        if not room_data['is_active']:
            await self.close(code=4005)
            return

        # ✅ NEW: Check if appointment is still confirmed
        if room_data['appointment_status'] not in ['confirmed', None]:
            # Appointment is completed/cancelled - close connection
            await self.close(code=4006)  # Custom code for expired appointment
            return

        self.room_type = room_data['room_type']

        await self.channel_layer.group_add(self.room_group_name, self.channel_name)
        await self.accept()

        messages = await self.get_message_history()

        await self.send(text_data=json.dumps({
            'type': 'connection_established',
            'room_id': self.room_id,
            'user_id': self.user.id,
            'messages': messages,
            'appointment_status': room_data['appointment_status']  # Send status to frontend
        }))

    async def disconnect(self, close_code):
        if hasattr(self, 'room_group_name'):
            await self.channel_layer.group_discard(self.room_group_name, self.channel_name)

    async def receive(self, text_data):
        try:
            data = json.parse(text_data)
        except json.JSONDecodeError:
            await self.send(text_data=json.dumps({"error": "Invalid JSON"}))
            return

        message_text = data.get('message', '').strip()
        if not message_text:
            return

        # ✅ Check appointment status before allowing message
        room_data = await self.get_room_data()
        if room_data and room_data['appointment_status'] != 'confirmed' and room_data['appointment_status'] is not None:
            await self.send(text_data=json.dumps({
                "type": "error",
                "error": "appointment_ended",
                "message": "This appointment has ended. You can no longer send messages."
            }))
            await self.close(code=4006)
            return

        saved_message = await self.save_message(message_text)
        if not saved_message:
            await self.send(text_data=json.dumps({"error": "Unable to save message"}))
            return

        full_name = await self.get_user_full_name()

        payload = {
            "id": saved_message.id,
            "room": self.room_id,
            "sender_id": self.user.id,
            "sender_username": getattr(self.user, "username", ""),
            "sender_full_name": full_name,
            "sender_role": getattr(self.user, "role", None),
            "content": saved_message.content,
            "timestamp": saved_message.timestamp.isoformat(),
            "is_read": saved_message.is_read
        }

        await self.channel_layer.group_send(
            self.room_group_name,
            {
                'type': 'chat_message',
                'message': payload
            }
        )

    async def chat_message(self, event):
        await self.send(text_data=json.dumps({
            'type': 'chat_message',
            'message': event['message']
        }))

    # ✅ Handler for appointment completion notification (sent via signals.py)
    async def appointment_completed(self, event):
        """Notify users that appointment has ended"""
        await self.send(text_data=json.dumps({
            'type': 'appointment_completed',
            'message': event.get('message', 'This appointment has ended. Chat is now closed.')
        }))
        await self.close(code=4006)

    @database_sync_to_async
    def get_message_history(self):
        try:
            messages = Message.objects.filter(room_id=self.room_id).select_related('sender').order_by('-timestamp')[:50]
            message_list = []
            for msg in reversed(messages):
                sender_name = msg.sender.username
                try:
                    if getattr(msg.sender, "role", None) == 'doctor':
                        sender_name = f"Dr. {msg.sender.doctor_profile.get_full_name()}"
                    elif getattr(msg.sender, "role", None) == 'patient':
                        sender_name = msg.sender.patient_profile.get_full_name()
                except Exception:
                    sender_name = getattr(msg.sender, "username", "")

                message_list.append({
                    'id': msg.id,
                    'sender_id': msg.sender.id,
                    'sender_username': getattr(msg.sender, "username", ""),
                    'sender_full_name': sender_name,
                    'sender_role': getattr(msg.sender, "role", None),
                    'content': msg.content,
                    'timestamp': msg.timestamp.isoformat(),
                    'is_read': msg.is_read
                })
            return message_list
        except Exception:
            return []

    @database_sync_to_async
    def get_room_data(self):
        try:
            room = ChatRoom.objects.prefetch_related('participants').select_related('appointment').get(id=self.room_id)
            
            # ✅ Get appointment status
            appointment_status = None
            if room.appointment:
                appointment_status = room.appointment.status
            
            return {
                'is_participant': room.participants.filter(id=self.user.id).exists(),
                'is_active': room.is_active,
                'room_type': room.room_type,
                'appointment_status': appointment_status  # ✅ NEW
            }
        except ChatRoom.DoesNotExist:
            return None

    @database_sync_to_async
    def save_message(self, content):
        try:
            room = ChatRoom.objects.select_related('appointment').get(id=self.room_id, is_active=True)
            
            # ✅ Check appointment status before saving
            if room.appointment and room.appointment.status != 'confirmed':
                return None
                
            if not room.participants.filter(id=self.user.id).exists():
                return None
                
            message = Message.objects.create(room=room, sender=self.user, content=content)
            room.updated_at = timezone.now()
            room.save()
            return message
        except Exception:
            return None

    @database_sync_to_async
    def get_user_full_name(self):
        try:
            if getattr(self.user, "role", None) == 'doctor':
                return f"Dr. {self.user.doctor_profile.get_full_name()}"
            elif getattr(self.user, "role", None) == 'patient':
                return self.user.patient_profile.get_full_name()
        except Exception:
            return getattr(self.user, "username", "")
        return getattr(self.user, "username", "")

    @database_sync_to_async
    def get_user_from_token(self, token):
        from rest_framework_simplejwt.tokens import AccessToken
        from django.contrib.auth import get_user_model
        UserModel = get_user_model()
        try:
            access_token = AccessToken(token)
            user_id = access_token['user_id']
            return UserModel.objects.get(id=user_id)
        except Exception:
            return None