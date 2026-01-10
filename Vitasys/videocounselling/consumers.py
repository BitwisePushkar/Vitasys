import json
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from appointments.models import Appointment
from .models import VideoCall
from django.utils import timezone


class VideoCallConsumer(AsyncWebsocketConsumer):

    async def connect(self):
        self.appointment_id = self.scope['url_route']['kwargs']['appointment_id']
        self.room_group_name = f'video_{self.appointment_id}'
        self.user = self.scope['user']

        if not self.user.is_authenticated:
            await self.close()
            return

        is_participant = await self.check_participant()
        if not is_participant:
            await self.close()
            return

        await self.channel_layer.group_add(self.room_group_name, self.channel_name)
        await self.accept()
        await self.channel_layer.group_send(self.room_group_name, {
            'type': 'user_joined',
            'user_id': self.user.id,
        })

    async def disconnect(self, close_code):
        await self.channel_layer.group_send(self.room_group_name, {
            'type': 'user_left',
            'user_id': self.user.id,
        })
        await self.channel_layer.group_discard(self.room_group_name, self.channel_name)
        await self.end_call_if_active()

    async def receive(self, text_data):
        data = json.loads(text_data)
        msg_type = data.get('type')

        if msg_type == 'offer':
            await self.channel_layer.group_send(self.room_group_name, {
                'type': 'signal_offer',
                'offer': data['offer'],
                'sender_id': self.user.id,
            })

        elif msg_type == 'answer':
            await self.channel_layer.group_send(self.room_group_name, {
                'type': 'signal_answer',
                'answer': data['answer'],
                'sender_id': self.user.id,
            })

        elif msg_type == 'ice_candidate':
            await self.channel_layer.group_send(self.room_group_name, {
                'type': 'signal_ice',
                'candidate': data['candidate'],
                'sender_id': self.user.id,
            })

        elif msg_type == 'end_call':
            await self.end_call_if_active()
            await self.channel_layer.group_send(self.room_group_name, {
                'type': 'call_ended',
                'sender_id': self.user.id,
            })

    async def user_joined(self, event):
        await self.send(text_data=json.dumps({
            'type': 'user_joined',
            'user_id': event['user_id'],
        }))

    async def user_left(self, event):
        await self.send(text_data=json.dumps({
            'type': 'user_left',
            'user_id': event['user_id'],
        }))

    async def signal_offer(self, event):
        if event['sender_id'] != self.user.id:
            await self.send(text_data=json.dumps({
                'type': 'offer',
                'offer': event['offer'],
            }))

    async def signal_answer(self, event):
        if event['sender_id'] != self.user.id:
            await self.send(text_data=json.dumps({
                'type': 'answer',
                'answer': event['answer'],
            }))

    async def signal_ice(self, event):
        if event['sender_id'] != self.user.id:
            await self.send(text_data=json.dumps({
                'type': 'ice_candidate',
                'candidate': event['candidate'],
            }))

    async def call_ended(self, event):
        await self.send(text_data=json.dumps({
            'type': 'call_ended',
        }))

    @database_sync_to_async
    def check_participant(self):
        try:
            appointment = Appointment.objects.get(id=self.appointment_id)
            user = self.user
            is_doctor = hasattr(user, 'doctor_profile') and appointment.doctor == user.doctor_profile
            is_patient = hasattr(user, 'patient_profile') and appointment.patient == user.patient_profile
            return is_doctor or is_patient
        except Appointment.DoesNotExist:
            return False

    @database_sync_to_async
    def end_call_if_active(self):
        try:
            video_call = VideoCall.objects.get(appointment_id=self.appointment_id)
            if video_call.status == 'active':
                video_call.status = 'ended'
                video_call.ended_at = timezone.now()
                video_call.save()
        except VideoCall.DoesNotExist:
            pass