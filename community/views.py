from rest_framework import status, generics, serializers
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.parsers import MultiPartParser, FormParser
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from django.db.models import Q

from .models import Post, Comment, Like, Category
from .serializers import (
    PostListSerializer,
    PostDetailSerializer,
    PostCreateSerializer,
    CommentSerializer,
    CommentCreateSerializer,
    CategorySerializer
)

class CategoryListView(APIView):
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        operation_summary="List all categories",
        operation_description="Fetch all post categories available in the community board. Default categories are auto-created if missing.",
        responses={
            200: openapi.Response(
                description="List of available categories",
                examples={
                    "application/json": [
                        {"id": 1, "name": "Cardiology", "description": "Heart-related topics"},
                        {"id": 2, "name": "Mental Health", "description": "Discussion on mental wellness"}
                    ]
                }
            )
        },
        tags=['Categories']
    )
    def get(self, request):
        default_categories = [
            {'name': 'General Medicine', 'description': 'General health topics'},
            {'name': 'Cardiology', 'description': 'Heart health'},
            {'name': 'Pediatrics', 'description': 'Child health'},
            {'name': 'Mental Health', 'description': 'Mental wellness'},
            {'name': 'Nutrition', 'description': 'Diet advice'},
            {'name': 'Fitness', 'description': 'Exercise tips'},
        ]
        for cat_data in default_categories:
            Category.objects.get_or_create(
                name=cat_data['name'],
                defaults={'description': cat_data['description']}
            )

        serializer = CategorySerializer(Category.objects.all(), many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
class PostListView(generics.ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = PostListSerializer

    @swagger_auto_schema(
        operation_summary="List all published posts",
        operation_description=(
            "Retrieve all published posts visible to the current user.\n\n"
            "- Patients see posts marked as visible to patients.\n"
            "- Doctors see posts marked as visible to staff.\n\n"
            "Optional: Filter posts by category slug using `?category=<slug>`."
        ),
        manual_parameters=[
            openapi.Parameter(
                'category',
                openapi.IN_QUERY,
                description="Filter posts by category slug (e.g., 'cardiology')",
                type=openapi.TYPE_STRING,
                required=False
            )
        ],
        responses={
            200: openapi.Response(
                description="List of published posts",
                examples={
                    "application/json": [
                        {"id": 1, "title": "Heart Health Basics", "author": "Dr. John Doe", "category": "Cardiology"},
                        {"id": 2, "title": "Managing Anxiety", "author": "Dr. Emily Smith", "category": "Mental Health"}
                    ]
                }
            )
        },
        tags=['Posts']
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)

    def get_queryset(self):
        user = self.request.user
        queryset = Post.objects.filter(status='published')

        if hasattr(user, 'patient_profile'):
            queryset = queryset.filter(visible_to_patients=True)
        elif hasattr(user, 'doctor_profile'):
            queryset = queryset.filter(visible_to_staff=True)

        category = self.request.query_params.get('category', None)
        if category:
            queryset = queryset.filter(category__slug=category)
        return queryset.order_by('-created_at')

class PostCreateView(APIView):
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]

    @swagger_auto_schema(
        operation_summary="Create a new community post",
        operation_description="Allows doctors to create posts (supports image upload).",
        request_body=PostCreateSerializer,
        consumes=['multipart/form-data'],
        responses={
            201: openapi.Response(
                description="Post created successfully",
                examples={
                    "application/json": {
                        "success": True,
                        "message": "Post created successfully",
                        "post": {
                            "id": 1,
                            "title": "Heart Health Basics",
                            "status": "published"
                        }
                    }
                }
            )
        },
        tags=['Posts']
    )

    def post(self, request):
        if not hasattr(request.user, 'doctor_profile'):
            return Response(
                {"error": "Only doctors can create posts"},
                status=status.HTTP_403_FORBIDDEN
            )
        serializer = PostCreateSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(author=request.user)
            return Response({
                "success": True,
                "message": "Post created successfully",
                "post": serializer.data
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class PostDetailView(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_summary="Get post details by slug",
        operation_description="Fetch full details for a published post. Automatically increments view count.",
        manual_parameters=[
            openapi.Parameter('slug', openapi.IN_PATH, description="Slug of the post", type=openapi.TYPE_STRING)
        ],
        responses={
            200: openapi.Response(
                description="Post details",
                examples={
                    "application/json": {
                        "id": 5,
                        "title": "Understanding Mental Health",
                        "content": "In-depth discussion...",
                        "views_count": 32
                    }
                }
            ),
            404: "Post not found"
        },
        tags=['Posts']
    )
    def get(self, request, slug):
        try:
            post = Post.objects.get(slug=slug, status='published')
            post.views_count += 1
            post.save(update_fields=['views_count'])
            serializer = PostDetailSerializer(post, context={'request': request})
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Post.DoesNotExist:
            return Response({"error": "Post not found"}, status=status.HTTP_404_NOT_FOUND)

    @swagger_auto_schema(
        operation_summary="Delete a post",
        operation_description="Delete a post owned by the logged-in doctor.",
        manual_parameters=[
            openapi.Parameter('slug', openapi.IN_PATH, description="Slug of the post to delete", type=openapi.TYPE_STRING)
        ],
        responses={
            204: "Post deleted successfully",
            403: "You can only delete your own posts",
            404: "Post not found"
        },
        tags=['Posts']
    )
    def delete(self, request, slug):
        if not hasattr(request.user, 'doctor_profile'):
            return Response(
                {"error": "Only doctors can delete posts"},
                status=status.HTTP_403_FORBIDDEN
            )
        
        try:
            post = Post.objects.get(slug=slug)
            if post.author != request.user:
                return Response(
                    {"error": "You can only delete your own posts"},
                    status=status.HTTP_403_FORBIDDEN
                )
            post.delete()
            return Response(
                {"message": "Post deleted successfully"},
                status=status.HTTP_204_NO_CONTENT
            )
        except Post.DoesNotExist:
            return Response(
                {"error": "Post not found"},
                status=status.HTTP_404_NOT_FOUND
            )

class PostLikeView(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_summary="Like or unlike a post",
        operation_description="Toggle like status for a given post. If already liked, it will unlike the post.",
        manual_parameters=[
            openapi.Parameter('slug', openapi.IN_PATH, description="Slug of the post", type=openapi.TYPE_STRING)
        ],
        responses={
            200: openapi.Response(
                description="Like toggled",
                examples={
                    "application/json": {"message": "Post liked", "total_likes": 15, "is_liked": True}
                }
            ),
            404: "Post not found"
        },
        tags=['Posts']
    )
    def post(self, request, slug):
        try:
            post = Post.objects.get(slug=slug, status='published')
            like, created = Like.objects.get_or_create(post=post, user=request.user)
            if not created:
                like.delete()
                return Response({"message": "Post unliked", "total_likes": post.likes.count(), "is_liked": False})
            return Response({"message": "Post liked", "total_likes": post.likes.count(), "is_liked": True})
        except Post.DoesNotExist:
            return Response({"error": "Post not found"}, status=status.HTTP_404_NOT_FOUND)
        
class CommentListView(generics.ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = CommentSerializer

    @swagger_auto_schema(
        operation_summary="List comments for a post",
        operation_description="Fetch all approved top-level comments (with nested replies) for a given post.",
        manual_parameters=[
            openapi.Parameter('slug', openapi.IN_PATH, description="Slug of the post", type=openapi.TYPE_STRING)
        ],
        responses={200: CommentSerializer(many=True)},
        tags=['Comments']
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)

    def get_queryset(self):
        slug = self.kwargs.get('slug')
        try:
            post = Post.objects.get(slug=slug, status='published')
            return post.comments.filter(is_approved=True, parent=None)
        except Post.DoesNotExist:
            return Comment.objects.none()


class CommentCreateView(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_summary="Add a comment to a post",
        operation_description="Allows users to comment on a post or reply to an existing comment by providing `parent` ID.",
        manual_parameters=[
            openapi.Parameter('slug', openapi.IN_PATH, description="Slug of the post", type=openapi.TYPE_STRING)
        ],
        request_body=CommentCreateSerializer,
        responses={
            201: openapi.Response(
                description="Comment created successfully",
                examples={
                    "application/json": {"id": 1, "content": "Great post!", "author": "john_doe"}
                }
            ),
            400: "Invalid input",
            404: "Post not found"
        },
        tags=['Comments']
    )
    def post(self, request, slug):
        try:
            post = Post.objects.get(slug=slug, status='published')
            serializer = CommentCreateSerializer(data=request.data)
            if serializer.is_valid():
                serializer.save(author=request.user, post=post)
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Post.DoesNotExist:
            return Response({"error": "Post not found"}, status=status.HTTP_404_NOT_FOUND)

class MyPostsView(generics.ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = PostListSerializer

    @swagger_auto_schema(
        operation_summary="List my posts",
        operation_description="Retrieve all posts authored by the currently authenticated user (any status).",
        responses={200: PostListSerializer(many=True)},
        tags=['Posts']
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)

    def get_queryset(self):
        return Post.objects.filter(author=self.request.user).order_by('-created_at')
