from rest_framework.throttling import UserRateThrottle


class ChatListThrottle(UserRateThrottle):
    scope = 'chat_list'


class ChatMessageThrottle(UserRateThrottle):
    scope = 'chat_message'


class ChatConnectionThrottle(UserRateThrottle):
    scope = 'chat_connection'


class ChatSearchThrottle(UserRateThrottle):
    scope = 'chat_search'


class ChatReadThrottle(UserRateThrottle):
    scope = 'chat_read'
