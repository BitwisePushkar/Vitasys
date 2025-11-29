from django.contrib import admin
from django.utils.html import format_html
from django.urls import reverse
from .models import Category, Post, PostImage, Comment, Like


@admin.register(Category)
class CategoryAdmin(admin.ModelAdmin):

    list_display = ['id', 'name', 'slug', 'post_count', 'created_at']
    search_fields = ['name', 'description']
    prepopulated_fields = {'slug': ('name',)}
    readonly_fields = ['created_at']
    
    def post_count(self, obj):
        count = obj.posts.count()
        return format_html(
            '<span style="font-weight: bold;">{} posts</span>',
            count
        )
    post_count.short_description = 'Total Posts'


class PostImageInline(admin.TabularInline):
    model = PostImage
    extra = 1
    fields = ['image', 'caption', 'uploaded_at']
    readonly_fields = ['uploaded_at']


@admin.register(Post)
class PostAdmin(admin.ModelAdmin):

    list_display = [
        'id',
        'title',
        'author_name_link',
        'category',
        'status_badge',
        'views_count',
        'likes_count',
        'comments_count',
        'published_at'
    ]
    
    list_filter = [
        'status',
        'category',
        'published_at',
        'created_at',
        'author__role'
    ]
    
    search_fields = [
        'title',
        'content',
        'author__username',
        'author__email'
    ]
    
    prepopulated_fields = {'slug': ('title',)}
    
    readonly_fields = [
        'created_at',
        'updated_at',
        'published_at',
        'views_count',
        'slug'
    ]
    
    fieldsets = (
        ('Post Content', {
            'fields': (
                'title',
                'slug',
                'author',
                'category',
                'content',
                'excerpt',
                'featured_image'
            )
        }),
        ('Status & Visibility', {
            'fields': (
                'status',
                'visible_to_all',
                'visible_to_staff',
                'visible_to_patients'
            )
        }),
        ('Statistics', {
            'fields': (
                'views_count',
                'published_at'
            ),
            'classes': ('collapse',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        })
    )
    
    inlines = [PostImageInline]
    
    date_hierarchy = 'created_at'
    ordering = ['-created_at']
    
    def author_name_link(self, obj):
        url = reverse('admin:Authapi_customuser_change', args=[obj.author.id])
        return format_html('<a href="{}">{}</a>', url, obj.author.username)
    author_name_link.short_description = 'Author'
    
    def status_badge(self, obj):
        colors = {
            'draft': '#6c757d',
            'published': '#28a745',
            'archived': '#dc3545'
        }
        color = colors.get(obj.status, '#6c757d')
        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 10px; '
            'border-radius: 3px; font-weight: bold; text-transform: uppercase;">{}</span>',
            color, obj.status
        )
    status_badge.short_description = 'Status'
    
    def likes_count(self, obj):
        count = obj.likes.count()
        return format_html('<span style="color: #dc3545;">❤ {}</span>', count)
    likes_count.short_description = 'Likes'
    
    def comments_count(self, obj):
        count = obj.comments.count()
        return format_html('<span style="color: #007bff;">💬 {}</span>', count)
    comments_count.short_description = 'Comments'
    
    actions = ['publish_posts', 'archive_posts', 'mark_draft']
    
    def publish_posts(self, request, queryset):
        from django.utils import timezone
        updated = queryset.update(status='published', published_at=timezone.now())
        self.message_user(request, f'{updated} post(s) published.')
    publish_posts.short_description = "Publish selected posts"
    
    def archive_posts(self, request, queryset):
        updated = queryset.update(status='archived')
        self.message_user(request, f'{updated} post(s) archived.')
    archive_posts.short_description = "Archive selected posts"
    
    def mark_draft(self, request, queryset):
        updated = queryset.update(status='draft')
        self.message_user(request, f'{updated} post(s) marked as draft.')
    mark_draft.short_description = "Mark as Draft"


@admin.register(PostImage)
class PostImageAdmin(admin.ModelAdmin):

    list_display = ['id', 'post_title', 'image_preview', 'caption', 'uploaded_at']
    list_filter = ['uploaded_at']
    search_fields = ['post__title', 'caption']
    readonly_fields = ['uploaded_at', 'image_preview']
    
    def post_title(self, obj):
        url = reverse('admin:community_post_change', args=[obj.post.id])
        return format_html('<a href="{}">{}</a>', url, obj.post.title)
    post_title.short_description = 'Post'
    
   
    def image_preview(self, obj):
        if obj.image:
            return format_html(
                '<img src="{}" style="max-width: 200px; max-height: 200px; border-radius: 5px;" />',
                obj.image.url
            )
        return '-'
    image_preview.short_description = 'Preview'


@admin.register(Comment)
class CommentAdmin(admin.ModelAdmin):

    list_display = [
        'id',
        'author_name_link',
        'post_title_link',
        'short_content',
        'is_approved_badge',
        'is_reply',
        'created_at'
    ]
    
    list_filter = [
        'is_approved',
        'created_at',
        'author__role'
    ]
    
    search_fields = [
        'author__username',
        'author__email',
        'post__title',
        'content'
    ]
    
    readonly_fields = ['created_at', 'updated_at']
    
    fieldsets = (
        ('Comment Details', {
            'fields': (
                'post',
                'author',
                'content',
                'parent'
            )
        }),
        ('Moderation', {
            'fields': ('is_approved',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        })
    )
    
    date_hierarchy = 'created_at'
    ordering = ['-created_at']
    
    def author_name_link(self, obj):
        url = reverse('admin:Authapi_customuser_change', args=[obj.author.id])
        return format_html('<a href="{}">{}</a>', url, obj.author.username)
    author_name_link.short_description = 'Author'
    
    def post_title_link(self, obj):
        url = reverse('admin:community_post_change', args=[obj.post.id])
        return format_html('<a href="{}">{}</a>', url, obj.post.title[:50])
    post_title_link.short_description = 'Post'
    
    def short_content(self, obj):
        return obj.content[:50] + '...' if len(obj.content) > 50 else obj.content
    short_content.short_description = 'Comment'
    
    def is_approved_badge(self, obj):
        if obj.is_approved:
            return format_html('<span style="color: green;">✓ Approved</span>')
        return format_html('<span style="color: red;">✗ Pending</span>')
    is_approved_badge.short_description = 'Status'
    
    def is_reply(self, obj):
        if obj.parent:
            return format_html('<span style="color: #007bff;">↳ Reply</span>')
        return '-'
    is_reply.short_description = 'Type'
    
    actions = ['approve_comments', 'disapprove_comments']
    
    def approve_comments(self, request, queryset):
        updated = queryset.update(is_approved=True)
        self.message_user(request, f'{updated} comment(s) approved.')
    approve_comments.short_description = "Approve selected comments"
    
    def disapprove_comments(self, request, queryset):
        updated = queryset.update(is_approved=False)
        self.message_user(request, f'{updated} comment(s) disapproved.')
    disapprove_comments.short_description = "Disapprove selected comments"


@admin.register(Like)
class LikeAdmin(admin.ModelAdmin):
    list_display = [
        'id',
        'user_name_link',
        'post_title_link',
        'created_at'
    ]
    
    list_filter = ['created_at']
    
    search_fields = [
        'user__username',
        'user__email',
        'post__title'
    ]
    
    readonly_fields = ['created_at']
    
    date_hierarchy = 'created_at'
    ordering = ['-created_at']
    
    def user_name_link(self, obj):
        url = reverse('admin:Authapi_customuser_change', args=[obj.user.id])
        return format_html('<a href="{}">{}</a>', url, obj.user.username)
    user_name_link.short_description = 'User'
    
    def post_title_link(self, obj):
        url = reverse('admin:community_post_change', args=[obj.post.id])
        return format_html('<a href="{}">{}</a>', url, obj.post.title[:50])
    post_title_link.short_description = 'Post'