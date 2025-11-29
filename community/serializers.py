from rest_framework import serializers
from .models import Post, Comment, Like, Category, PostImage
from Authapi.models import CustomUser

class CategorySerializer(serializers.ModelSerializer):
    """Serializer for post categories"""
    class Meta:
        model = Category
        fields = ['id', 'name', 'slug', 'description']


class PostImageSerializer(serializers.ModelSerializer):
    """Serializer for post images"""
    class Meta:
        model = PostImage
        fields = ['id', 'image', 'caption', 'uploaded_at']


class CommentSerializer(serializers.ModelSerializer):
    """Serializer for displaying comments with author info and replies"""
    author_name = serializers.SerializerMethodField(help_text="Display name of the comment author")
    author_role = serializers.SerializerMethodField(help_text="Role of the author (doctor/patient)")
    replies = serializers.SerializerMethodField(help_text="List of replies to this comment")
    
    class Meta:
        model = Comment
        fields = [
            'id',
            'author',
            'author_name',
            'author_role',
            'content',
            'parent',
            'created_at',
            'updated_at',
            'replies'
        ]
        read_only_fields = ['author', 'created_at']
    
    def get_author_name(self, obj):
        try:
            if hasattr(obj.author, 'doctor_profile'):
                return f"Dr. {obj.author.doctor_profile.get_full_name()}"
            elif hasattr(obj.author, 'patient_profile'):
                return obj.author.patient_profile.get_full_name()
        except:
            return obj.author.username
    
    def get_author_role(self, obj):
        return getattr(obj.author, 'role', 'unknown')
    
    def get_replies(self, obj):
        if obj.parent is None:
            replies = obj.replies.filter(is_approved=True)
            return CommentSerializer(replies, many=True).data
        return []


class PostListSerializer(serializers.ModelSerializer):
    """Serializer for listing posts with summary information"""
    author_name = serializers.SerializerMethodField(help_text="Display name of the post author")
    author_role = serializers.SerializerMethodField(help_text="Role of the author")
    category_name = serializers.CharField(source='category.name', read_only=True, help_text="Category name")
    total_likes = serializers.SerializerMethodField(help_text="Total number of likes")
    total_comments = serializers.SerializerMethodField(help_text="Total number of top-level comments")
    is_liked = serializers.SerializerMethodField(help_text="Whether current user has liked this post")
    
    class Meta:
        model = Post
        fields = [
            'id',
            'title',
            'slug',
            'author',
            'author_name',
            'author_role',
            'category_name',
            'excerpt',
            'featured_image',
            'status',
            'created_at',
            'published_at',
            'views_count',
            'total_likes',
            'total_comments',
            'is_liked'
        ]
    
    def get_author_name(self, obj):
        try:
            if hasattr(obj.author, 'doctor_profile'):
                return f"Dr. {obj.author.doctor_profile.get_full_name()}"
            elif hasattr(obj.author, 'patient_profile'):
                return obj.author.patient_profile.get_full_name()
        except:
            return obj.author.username
    
    def get_author_role(self, obj):
        return getattr(obj.author, 'role', 'unknown')
    
    def get_total_likes(self, obj):
        return obj.likes.count()
    
    def get_total_comments(self, obj):
        return obj.comments.filter(is_approved=True, parent=None).count()
    
    def get_is_liked(self, obj):
        request = self.context.get('request')
        if request and request.user.is_authenticated:
            return Like.objects.filter(post=obj, user=request.user).exists()
        return False


class PostDetailSerializer(serializers.ModelSerializer):
    """Serializer for detailed post view including full content, images, and comments"""
    author_name = serializers.SerializerMethodField(help_text="Display name of the post author")
    author_role = serializers.SerializerMethodField(help_text="Role of the author")
    category = CategorySerializer(read_only=True)
    images = PostImageSerializer(many=True, read_only=True, help_text="Additional images for the post")
    comments = serializers.SerializerMethodField(help_text="All approved comments on this post")
    total_likes = serializers.SerializerMethodField(help_text="Total number of likes")
    is_liked = serializers.SerializerMethodField(help_text="Whether current user has liked this post")
    
    class Meta:
        model = Post
        fields = [
            'id',
            'title',
            'slug',
            'author',
            'author_name',
            'author_role',
            'category',
            'content',
            'excerpt',
            'featured_image',
            'images',
            'status',
            'created_at',
            'updated_at',
            'published_at',
            'views_count',
            'total_likes',
            'is_liked',
            'comments'
        ]
    
    def get_author_name(self, obj):
        try:
            if hasattr(obj.author, 'doctor_profile'):
                return f"Dr. {obj.author.doctor_profile.get_full_name()}"
            elif hasattr(obj.author, 'patient_profile'):
                return obj.author.patient_profile.get_full_name()
        except:
            return obj.author.username
    
    def get_author_role(self, obj):
        return getattr(obj.author, 'role', 'unknown')
    
    def get_total_likes(self, obj):
        return obj.likes.count()
    
    def get_is_liked(self, obj):
        request = self.context.get('request')
        if request and request.user.is_authenticated:
            return Like.objects.filter(post=obj, user=request.user).exists()
        return False
    
    def get_comments(self, obj):
        comments = obj.comments.filter(is_approved=True, parent=None)
        return CommentSerializer(comments, many=True).data


class PostCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating new posts"""
    class Meta:
        model = Post
        fields = [
            'title',
            'category',
            'content',
            'excerpt',
            'featured_image',
            'status'
        ]
        extra_kwargs = {
            'title': {'help_text': 'Post title (max 200 characters)'},
            'category': {'help_text': 'Category ID for the post'},
            'content': {'help_text': 'Full content of the post (supports markdown)'},
            'excerpt': {'help_text': 'Brief summary (max 300 characters)'},
            'featured_image': {'help_text': 'Main image for the post'},
            'status': {'help_text': 'Post status: draft, published, or archived'}
        }


class CommentCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating comments"""
    class Meta:
        model = Comment
        fields = ['content', 'parent']
        extra_kwargs = {
            'content': {'help_text': 'Comment text content'},
            'parent': {'help_text': 'Parent comment ID for replies (null for top-level comments)', 'required': False}
        }