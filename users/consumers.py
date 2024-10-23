import json
import jwt
import logging
import urllib.parse
from users import models
from channels.db import database_sync_to_async
from channels.generic.websocket import AsyncWebsocketConsumer
from django.core.exceptions import PermissionDenied
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken

log = logging.getLogger("main")

class ChatConsumer(AsyncWebsocketConsumer):

    async def token_parser(self):
        raw_query = self.scope["query_string"]
        decoded_query = raw_query.decode("utf-8")
        query_params = urllib.parse.parse_qs(decoded_query)
        token = query_params.get("token", [None])[0]
        return token
    
    @database_sync_to_async
    def get_user_from_token(self, user_id):
        # Synchronous ORM query inside an async method
        return models.User.objects.get(id=user_id)

    @database_sync_to_async
    def set_status_on_and_last_seen_added(self):
        # Synchronous ORM query inside an async method
        self.user.status = True
        self.user.save()
    @database_sync_to_async
    def set_status_off_and_last_seen_added(self):
        # Synchronous ORM query inside an async method
        self.user.status = False
        self.user.save()                                       
    
    async def authenticate_user(self, token):
        print(self.token_parser())
        token = await self.token_parser()
        decoded = AccessToken(token)
        print("Decoded:" + "==="*50 + f"{decoded['user_id']}")
        user = await self.get_user_from_token(decoded["user_id"])
        print("User:" + "==="*50 + f"{user}")
        self.scope["user"] = user
        return user

        # try:
        #     payload = jwt.decode(token, 'your_secret_key', algorithms=["HS256"])
        #     user_id = payload.get('user_id')

        #     if not user_id:
        #         raise PermissionDenied("Invalid token!")

        #     user = models.User.objects.get(id=user_id)
        #     self.scope["user"] = user
        #     return user
        # except (jwt.ExpiredSignatureError, jwt.DecodeError, jwt.InvalidTokenError) as e:
        #     raise PermissionDenied("Invalid token!")

    async def connect(self):

        await self.accept()
        token = await self.token_parser()

        print(f"token: {token}")
        room_name = "room_name" 
        self.room_name = room_name
        self.room_group_name = f'chat_{room_name}'


        try:
            user = await self.authenticate_user(token)
            self.user = user
            print(f"Authenticated user: {user.email}")
            await self.set_status_on_and_last_seen_added()

        except Exception as e:
            log.error(e)
            await self.close()
            return

        await self.channel_layer.group_add(
            self.room_group_name,
            self.channel_name
        )


        await self.channel_layer.group_send(
            self.room_group_name,
            {
                'type': 'chat_message',
                'message': f'{self.channel_name} has joined the chat!',
            }
        )


    async def receive(self, text_data=None, bytes_data=None):
        if text_data:
            text_data_json = json.loads(text_data)
            message = text_data_json['message']

            await self.channel_layer.group_send(
                self.room_group_name,
                {
                    'type': 'chat_message',
                    'message': message,
                }
            )

    async def chat_message(self, event):
        await self.send(text_data=json.dumps({
            'message': event['message']
        }))

    async def disconnect(self, close_code):
        print("DISCONNECT: " + "==="*50 + self.user.email)
        await self.set_status_off_and_last_seen_added()

        # # Remove this connection from the group on disconnect
        # await self.channel_layer.group_discard(
        #     self.room_group_name,
        #     self.channel_name
        # )

        # # Optionally notify the group that a user has left
        # await self.channel_layer.group_send(
        #     self.room_group_name,
        #     {
        #         'type': 'chat_message',
        #         'message': f'{self.channel_name} has left the chat!',
        #     }
        # )

        pass
