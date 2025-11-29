from django.urls import path
from .views import (
    CategoryListView,
    PostListView,
    PostCreateView,
    PostDetailView,
    PostLikeView,
    CommentListView,
    CommentCreateView,
    MyPostsView
)

app_name = 'community'

urlpatterns = [

    path('categories/', CategoryListView.as_view(), name='category-list'),
    

    path('posts/', PostListView.as_view(), name='post-list'),
    path('posts/create/', PostCreateView.as_view(), name='post-create'),
    path('posts/my-posts/', MyPostsView.as_view(), name='my-posts'),
    path('posts/<slug:slug>/', PostDetailView.as_view(), name='post-detail'),
    path('posts/<slug:slug>/like/', PostLikeView.as_view(), name='post-like'),
    
 
    path('posts/<slug:slug>/comments/', CommentListView.as_view(), name='comment-list'),
    path('posts/<slug:slug>/comments/create/', CommentCreateView.as_view(), name='comment-create'),
]