import json
from channels.generic.websocket import AsyncWebsocketConsumer
from asgiref.sync import sync_to_async
from django.contrib.auth import get_user_model
from django.utils import timezone
from .models import User, Message, Chat

class ChatConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.user = self.scope["user"]
        print(f"User from scope: {self.user}")

        if not self.user.is_authenticated:
            await self.close()
            return

        # Join the room group for this user
        self.room_group_name = f"user_{self.user.id}"
        await self.channel_layer.group_add(self.room_group_name, self.channel_name)

        # Accept the WebSocket connection
        await self.accept()

        # Update the user's status to online
        await self.update_user_status(True)

        print(f"WebSocket connected for user: {self.user.username}")


    async def disconnect(self, close_code):
        # Update the user's status to offline
        await self.update_user_status(False)

        # Leave the WebSocket group for the user
        await self.channel_layer.group_discard(
            self.room_group_name,
            self.channel_name
        )

        print(f"WebSocket disconnected for user: {self.user.username} with code: {close_code}")

    async def receive(self, text_data):
        try:
            data = json.loads(text_data)
            if data['type'] == 'chat.message':
                await self.broadcast_message(data)
            elif data['type'] == 'get.users':
                await self.send_users_list()
        except json.JSONDecodeError as e:
            print(f"JSON decode error: {e}")
            await self.close()
        except Exception as e:
            print(f"Error in receive: {e}")
            await self.close()


    @sync_to_async
    def update_user_status(self, status):
        # Update the user's logged-in status in the database
        self.user.is_logged_in = status
        self.user.save()

    @sync_to_async
    def get_users_list(self):
        # Retrieve a list of all users excluding the current user
        users = User.objects.exclude(id=self.user.id)
        return [{'id': u.id, 'username': u.username, 'online': u.is_logged_in} for u in users]

    async def send_users_list(self):
        # Get the list of users and send it to the WebSocket
        users = await self.get_users_list()
        await self.send(text_data=json.dumps({'type': 'users.list', 'users': users}))

    @sync_to_async
    def save_message(self, recipient_id, content):
        # Get the recipient user and create a chat if it doesn't exist
        recipient = User.objects.get(id=recipient_id)
        chat, _ = Chat.objects.get_or_create(participants__in=[self.user, recipient])
        return Message.objects.create(chat=chat, sender=self.user, recipient=recipient, content=content)

    async def broadcast_message(self, data):
        # Save the message and broadcast it to the recipient's WebSocket
        message = await self.save_message(data['recipient'], data['content'])
        recipient_group = f"user_{data['recipient']}"
        
        # Send the message to the recipient's group
        await self.channel_layer.group_send(
            recipient_group,
            {
                'type': 'chat.message',
                'message': {
                    'sender': self.user.username,
                    'content': message.content,
                    'timestamp': str(message.timestamp),
                }
            }
        )

    async def chat_message(self, event):
        # Extract the message content from the event
        message = event['message']

        # Send the message data to the WebSocket
        await self.send(text_data=json.dumps({
            'type': 'chat.message',
            'message': message
        }))
