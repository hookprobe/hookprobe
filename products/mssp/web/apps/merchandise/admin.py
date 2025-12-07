"""
Merchandise Admin Interface
Django admin configuration for product management.
"""

from django.contrib import admin
from django.utils.html import format_html
from .models import (
    ProductCategory,
    Product,
    ProductVariant,
    ProductImage,
    Order,
    OrderItem
)


class ProductImageInline(admin.TabularInline):
    """Inline admin for product images."""
    model = ProductImage
    extra = 1
    fields = ['image', 'alt_text', 'order', 'is_primary']


class ProductVariantInline(admin.TabularInline):
    """Inline admin for product variants."""
    model = ProductVariant
    extra = 1
    fields = ['variant_type', 'name', 'sku', 'price_adjustment', 'stock_quantity', 'active']


@admin.register(ProductCategory)
class ProductCategoryAdmin(admin.ModelAdmin):
    """Admin interface for product categories."""
    list_display = ['name', 'slug', 'product_count', 'order', 'active', 'created_at']
    list_filter = ['active', 'created_at']
    search_fields = ['name', 'slug', 'description']
    prepopulated_fields = {'slug': ('name',)}
    ordering = ['order', 'name']

    fieldsets = (
        ('Basic Information', {
            'fields': ('name', 'slug', 'description', 'image')
        }),
        ('Display Settings', {
            'fields': ('order', 'active')
        }),
    )


@admin.register(Product)
class ProductAdmin(admin.ModelAdmin):
    """Admin interface for products."""
    list_display = [
        'name',
        'category',
        'price_display',
        'stock_status',
        'sku',
        'active',
        'featured',
        'created_at'
    ]
    list_filter = ['active', 'featured', 'category', 'created_at']
    search_fields = ['name', 'sku', 'description']
    prepopulated_fields = {'slug': ('name',)}
    readonly_fields = ['created_at', 'updated_at']
    inlines = [ProductImageInline, ProductVariantInline]

    fieldsets = (
        ('Basic Information', {
            'fields': ('name', 'slug', 'category', 'description', 'short_description')
        }),
        ('Pricing', {
            'fields': ('price', 'compare_at_price')
        }),
        ('Inventory', {
            'fields': ('sku', 'track_inventory', 'stock_quantity', 'low_stock_threshold')
        }),
        ('Product Specifications', {
            'fields': ('weight', 'dimensions', 'has_variants'),
            'classes': ('collapse',)
        }),
        ('SEO', {
            'fields': ('seo_title', 'seo_description'),
            'classes': ('collapse',)
        }),
        ('Status', {
            'fields': ('active', 'featured')
        }),
        ('Metadata', {
            'fields': ('created_by', 'created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )

    def price_display(self, obj):
        """Display price with sale indicator."""
        if obj.is_on_sale:
            return format_html(
                '<span style="text-decoration: line-through; color: #999;">${}</span> '
                '<strong style="color: #e74c3c;">${}</strong> '
                '<span style="color: #e74c3c;">(-{}%)</span>',
                obj.compare_at_price,
                obj.price,
                obj.discount_percentage
            )
        return f'${obj.price}'
    price_display.short_description = 'Price'

    def stock_status(self, obj):
        """Display stock status with color coding."""
        if not obj.track_inventory:
            return format_html('<span style="color: #95a5a6;">Not tracked</span>')
        elif not obj.is_in_stock:
            return format_html('<span style="color: #e74c3c;">Out of stock</span>')
        elif obj.is_low_stock:
            return format_html(
                '<span style="color: #f39c12;">{} (Low stock)</span>',
                obj.stock_quantity
            )
        return format_html('<span style="color: #27ae60;">{}</span>', obj.stock_quantity)
    stock_status.short_description = 'Stock'

    def save_model(self, request, obj, form, change):
        """Save model and set created_by."""
        if not change:
            obj.created_by = request.user
        super().save_model(request, obj, form, change)


@admin.register(ProductVariant)
class ProductVariantAdmin(admin.ModelAdmin):
    """Admin interface for product variants."""
    list_display = ['__str__', 'sku', 'price_display', 'stock_quantity', 'active']
    list_filter = ['active', 'variant_type', 'product__category']
    search_fields = ['name', 'sku', 'product__name']

    fieldsets = (
        ('Variant Information', {
            'fields': ('product', 'variant_type', 'name')
        }),
        ('Pricing', {
            'fields': ('price_adjustment',)
        }),
        ('Inventory', {
            'fields': ('sku', 'stock_quantity')
        }),
        ('Status', {
            'fields': ('active',)
        }),
    )

    def price_display(self, obj):
        """Display total price."""
        return f'${obj.total_price}'
    price_display.short_description = 'Price'


class OrderItemInline(admin.TabularInline):
    """Inline admin for order items."""
    model = OrderItem
    extra = 0
    readonly_fields = ['product_name', 'product_sku', 'variant_name', 'unit_price', 'quantity', 'total_price']
    can_delete = False

    def has_add_permission(self, request, obj=None):
        return False


@admin.register(Order)
class OrderAdmin(admin.ModelAdmin):
    """Admin interface for orders."""
    list_display = [
        'order_number',
        'customer_name',
        'customer_email',
        'total_display',
        'status_display',
        'payment_status_display',
        'created_at'
    ]
    list_filter = ['status', 'payment_status', 'created_at', 'payment_method']
    search_fields = ['order_number', 'customer_email', 'customer_name', 'payment_transaction_id']
    readonly_fields = [
        'order_number',
        'uuid',
        'subtotal',
        'shipping_cost',
        'tax',
        'total',
        'created_at',
        'updated_at',
        'paid_at',
        'shipped_at',
        'delivered_at'
    ]
    inlines = [OrderItemInline]
    date_hierarchy = 'created_at'

    fieldsets = (
        ('Order Information', {
            'fields': ('order_number', 'uuid', 'status', 'payment_status')
        }),
        ('Customer Information', {
            'fields': ('customer', 'customer_name', 'customer_email')
        }),
        ('Shipping Address', {
            'fields': (
                'shipping_address_line1',
                'shipping_address_line2',
                'shipping_city',
                'shipping_state',
                'shipping_postal_code',
                'shipping_country',
                'shipping_phone'
            )
        }),
        ('Order Totals', {
            'fields': ('subtotal', 'shipping_cost', 'tax', 'total')
        }),
        ('Payment Information', {
            'fields': ('payment_method', 'payment_transaction_id')
        }),
        ('Notes', {
            'fields': ('customer_notes', 'admin_notes'),
            'classes': ('collapse',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at', 'paid_at', 'shipped_at', 'delivered_at'),
            'classes': ('collapse',)
        }),
    )

    def total_display(self, obj):
        """Display order total."""
        return f'${obj.total}'
    total_display.short_description = 'Total'

    def status_display(self, obj):
        """Display status with color coding."""
        colors = {
            'pending': '#f39c12',
            'processing': '#3498db',
            'shipped': '#9b59b6',
            'delivered': '#27ae60',
            'cancelled': '#e74c3c',
            'refunded': '#95a5a6',
        }
        color = colors.get(obj.status, '#000')
        return format_html(
            '<span style="color: {}; font-weight: bold;">{}</span>',
            color,
            obj.get_status_display()
        )
    status_display.short_description = 'Status'

    def payment_status_display(self, obj):
        """Display payment status with color coding."""
        colors = {
            'pending': '#f39c12',
            'paid': '#27ae60',
            'failed': '#e74c3c',
            'refunded': '#95a5a6',
        }
        color = colors.get(obj.payment_status, '#000')
        return format_html(
            '<span style="color: {};">{}</span>',
            color,
            obj.get_payment_status_display()
        )
    payment_status_display.short_description = 'Payment'

    actions = ['mark_as_paid', 'mark_as_shipped', 'mark_as_delivered', 'cancel_orders']

    def mark_as_paid(self, request, queryset):
        """Mark selected orders as paid."""
        for order in queryset:
            order.mark_as_paid(transaction_id=f'MOCK-{order.order_number}')
        self.message_user(request, f'{queryset.count()} orders marked as paid.')
    mark_as_paid.short_description = 'Mark as paid (mock payment)'

    def mark_as_shipped(self, request, queryset):
        """Mark selected orders as shipped."""
        for order in queryset.filter(payment_status='paid'):
            order.mark_as_shipped()
        self.message_user(request, f'{queryset.count()} orders marked as shipped.')
    mark_as_shipped.short_description = 'Mark as shipped'

    def mark_as_delivered(self, request, queryset):
        """Mark selected orders as delivered."""
        for order in queryset.filter(status='shipped'):
            order.mark_as_delivered()
        self.message_user(request, f'{queryset.count()} orders marked as delivered.')
    mark_as_delivered.short_description = 'Mark as delivered'

    def cancel_orders(self, request, queryset):
        """Cancel selected orders."""
        for order in queryset:
            order.cancel()
        self.message_user(request, f'{queryset.count()} orders cancelled.')
    cancel_orders.short_description = 'Cancel orders'
