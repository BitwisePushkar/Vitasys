
from django.core.management.base import BaseCommand
from appointments.models import Appointment
from chat_room.models import ChatRoom


class Command(BaseCommand):
    help = 'Creates missing chat rooms for confirmed appointments'

    def handle(self, *args, **kwargs):
        confirmed_appointments = Appointment.objects.filter(status='confirmed')
        
        self.stdout.write(f"Found {confirmed_appointments.count()} confirmed appointments")
        
        created_count = 0
        existing_count = 0
        
        for appointment in confirmed_appointments:
            chat_room = ChatRoom.objects.filter(appointment=appointment).first()
            
            if chat_room:
                if not chat_room.is_active:
                    chat_room.is_active = True
                    chat_room.save()
                    self.stdout.write(self.style.WARNING(
                        f"Reactivated chat room for appointment {appointment.id}"
                    ))
                else:
                    existing_count += 1
                    self.stdout.write(self.style.SUCCESS(
                        f"Chat room already exists for appointment {appointment.id}"
                    ))
            else:
                try:
                    room = ChatRoom.objects.create(
                        appointment=appointment,
                        room_type='patient_doctor',
                        is_active=True,
                    )
                    room.participants.add(appointment.patient.user, appointment.doctor.user)
                    created_count += 1
                    self.stdout.write(self.style.SUCCESS(
                        f"✅ Created chat room {room.id} for appointment {appointment.id}"
                    ))
                except Exception as e:
                    self.stdout.write(self.style.ERROR(
                        f"❌ Failed to create chat room for appointment {appointment.id}: {e}"
                    ))
        
        self.stdout.write(self.style.SUCCESS(
            f"\n✅ Summary: {created_count} created, {existing_count} already existed"
        ))