"""
Merchandise Models
Product catalog, inventory, and order management.
"""

from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from django.core.validators import MinValueValidator
from decimal import Decimal
import uuid


class ProductCategory(models.Model):
    """
    Product categories for merchandise.
    Default categories: Homepod Toys, T-shirts, Stickers
    """
    name = models.CharField(max_length=100, unique=True)
    slug = models.SlugField(max_length=100, unique=True)
    description = models.TextField(blank=True)
    image = models.ImageField(upload_to='merchandise/categories/', blank=True, null=True)

    # Display order
    order = models.IntegerField(default=0, help_text="Display order (lower numbers first)")

    # Status
    active = models.BooleanField(default=True)

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['order', 'name']
        verbose_name = 'Product Category'
        verbose_name_plural = 'Product Categories'

    def __str__(self):
        return self.name

    @property
    def product_count(self):
        """Count of active products in this category."""
        return self.products.filter(active=True).count()


class Product(models.Model):
    """
    Product catalog.
    """
    # Basic information
    name = models.CharField(max_length=200)
    slug = models.SlugField(max_length=200, unique=True)
    description = models.TextField()
    short_description = models.CharField(max_length=300, blank=True)

    # Category
    category = models.ForeignKey(ProductCategory, on_delete=models.CASCADE, related_name='products')

    # Pricing
    price = models.DecimalField(max_digits=10, decimal_places=2, validators=[MinValueValidator(Decimal('0.01'))])
    compare_at_price = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        null=True,
        blank=True,
        help_text="Original price for sale items"
    )

    # Inventory
    sku = models.CharField(max_length=50, unique=True, help_text="Stock Keeping Unit")
    stock_quantity = models.IntegerField(default=0, validators=[MinValueValidator(0)])
    low_stock_threshold = models.IntegerField(default=5, help_text="Alert when stock falls below this")
    track_inventory = models.BooleanField(default=True, help_text="Track inventory for this product")

    # Product specifications
    weight = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True, help_text="Weight in kg")
    dimensions = models.CharField(max_length=100, blank=True, help_text="Dimensions (L x W x H)")

    # Variants (e.g., sizes, colors)
    has_variants = models.BooleanField(default=False)

    # SEO
    seo_title = models.CharField(max_length=200, blank=True)
    seo_description = models.TextField(max_length=300, blank=True)

    # Status
    active = models.BooleanField(default=True)
    featured = models.BooleanField(default=False)

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='products_created')

    class Meta:
        ordering = ['-created_at']
        verbose_name = 'Product'
        verbose_name_plural = 'Products'

    def __str__(self):
        return self.name

    @property
    def is_on_sale(self):
        """Check if product is on sale."""
        return self.compare_at_price and self.compare_at_price > self.price

    @property
    def discount_percentage(self):
        """Calculate discount percentage."""
        if self.is_on_sale:
            return int(((self.compare_at_price - self.price) / self.compare_at_price) * 100)
        return 0

    @property
    def is_in_stock(self):
        """Check if product is in stock."""
        if not self.track_inventory:
            return True
        return self.stock_quantity > 0

    @property
    def is_low_stock(self):
        """Check if stock is low."""
        if not self.track_inventory:
            return False
        return 0 < self.stock_quantity <= self.low_stock_threshold

    def reduce_stock(self, quantity):
        """Reduce stock quantity."""
        if self.track_inventory:
            self.stock_quantity = max(0, self.stock_quantity - quantity)
            self.save()

    def increase_stock(self, quantity):
        """Increase stock quantity."""
        if self.track_inventory:
            self.stock_quantity += quantity
            self.save()


class ProductVariant(models.Model):
    """
    Product variants (sizes, colors, etc.).
    Example: T-shirt with sizes S, M, L, XL
    """
    product = models.ForeignKey(Product, on_delete=models.CASCADE, related_name='variants')

    # Variant details
    name = models.CharField(max_length=100, help_text="e.g., 'Small', 'Red', 'Blue'")
    variant_type = models.CharField(max_length=50, help_text="e.g., 'Size', 'Color'")

    # Pricing (optional override)
    price_adjustment = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        default=0,
        help_text="Price adjustment from base product price"
    )

    # Inventory
    sku = models.CharField(max_length=50, unique=True, help_text="Variant SKU")
    stock_quantity = models.IntegerField(default=0, validators=[MinValueValidator(0)])

    # Status
    active = models.BooleanField(default=True)

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['variant_type', 'name']
        verbose_name = 'Product Variant'
        verbose_name_plural = 'Product Variants'
        unique_together = ['product', 'variant_type', 'name']

    def __str__(self):
        return f"{self.product.name} - {self.variant_type}: {self.name}"

    @property
    def total_price(self):
        """Calculate total price including adjustment."""
        return self.product.price + self.price_adjustment

    @property
    def is_in_stock(self):
        """Check if variant is in stock."""
        return self.stock_quantity > 0


class ProductImage(models.Model):
    """
    Product images (multiple images per product).
    """
    product = models.ForeignKey(Product, on_delete=models.CASCADE, related_name='images')
    image = models.ImageField(upload_to='merchandise/products/')
    alt_text = models.CharField(max_length=200, blank=True)
    order = models.IntegerField(default=0, help_text="Display order (lower numbers first)")
    is_primary = models.BooleanField(default=False, help_text="Primary product image")

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['order', '-is_primary']
        verbose_name = 'Product Image'
        verbose_name_plural = 'Product Images'

    def __str__(self):
        return f"Image for {self.product.name}"

    def save(self, *args, **kwargs):
        # If this is set as primary, unset other primary images for this product
        if self.is_primary:
            ProductImage.objects.filter(product=self.product, is_primary=True).update(is_primary=False)
        super().save(*args, **kwargs)


class Order(models.Model):
    """
    Customer orders (mock payment for now).
    """
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('processing', 'Processing'),
        ('shipped', 'Shipped'),
        ('delivered', 'Delivered'),
        ('cancelled', 'Cancelled'),
        ('refunded', 'Refunded'),
    ]

    PAYMENT_STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('paid', 'Paid'),
        ('failed', 'Failed'),
        ('refunded', 'Refunded'),
    ]

    # Order identification
    order_number = models.CharField(max_length=50, unique=True, editable=False)
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)

    # Customer information
    customer = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='orders')
    customer_email = models.EmailField()
    customer_name = models.CharField(max_length=200)

    # Shipping address
    shipping_address_line1 = models.CharField(max_length=200)
    shipping_address_line2 = models.CharField(max_length=200, blank=True)
    shipping_city = models.CharField(max_length=100)
    shipping_state = models.CharField(max_length=100, blank=True)
    shipping_postal_code = models.CharField(max_length=20)
    shipping_country = models.CharField(max_length=100)
    shipping_phone = models.CharField(max_length=50, blank=True)

    # Order totals
    subtotal = models.DecimalField(max_digits=10, decimal_places=2)
    shipping_cost = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    tax = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    total = models.DecimalField(max_digits=10, decimal_places=2)

    # Status
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    payment_status = models.CharField(max_length=20, choices=PAYMENT_STATUS_CHOICES, default='pending')

    # Payment information (mock for now)
    payment_method = models.CharField(max_length=50, default='mock')
    payment_transaction_id = models.CharField(max_length=200, blank=True)

    # Notes
    customer_notes = models.TextField(blank=True)
    admin_notes = models.TextField(blank=True)

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    paid_at = models.DateTimeField(null=True, blank=True)
    shipped_at = models.DateTimeField(null=True, blank=True)
    delivered_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['-created_at']
        verbose_name = 'Order'
        verbose_name_plural = 'Orders'

    def __str__(self):
        return f"Order #{self.order_number}"

    def save(self, *args, **kwargs):
        if not self.order_number:
            # Generate order number: HP-YYYYMMDD-XXXXX
            from django.utils.timezone import now
            date_str = now().strftime('%Y%m%d')
            last_order = Order.objects.filter(order_number__startswith=f'HP-{date_str}').order_by('-order_number').first()
            if last_order:
                last_number = int(last_order.order_number.split('-')[-1])
                new_number = last_number + 1
            else:
                new_number = 1
            self.order_number = f'HP-{date_str}-{new_number:05d}'

        super().save(*args, **kwargs)

    @property
    def item_count(self):
        """Total number of items in order."""
        return sum(item.quantity for item in self.items.all())

    def mark_as_paid(self, transaction_id=None):
        """Mark order as paid."""
        self.payment_status = 'paid'
        self.paid_at = timezone.now()
        if transaction_id:
            self.payment_transaction_id = transaction_id
        self.save()

    def mark_as_shipped(self):
        """Mark order as shipped."""
        self.status = 'shipped'
        self.shipped_at = timezone.now()
        self.save()

    def mark_as_delivered(self):
        """Mark order as delivered."""
        self.status = 'delivered'
        self.delivered_at = timezone.now()
        self.save()

    def cancel(self):
        """Cancel order and restore stock."""
        self.status = 'cancelled'
        self.save()

        # Restore stock for all items
        for item in self.items.all():
            if item.product_variant:
                item.product_variant.stock_quantity += item.quantity
                item.product_variant.save()
            else:
                item.product.increase_stock(item.quantity)


class OrderItem(models.Model):
    """
    Individual items in an order.
    """
    order = models.ForeignKey(Order, on_delete=models.CASCADE, related_name='items')
    product = models.ForeignKey(Product, on_delete=models.SET_NULL, null=True)
    product_variant = models.ForeignKey(ProductVariant, on_delete=models.SET_NULL, null=True, blank=True)

    # Snapshot of product details at time of order
    product_name = models.CharField(max_length=200)
    product_sku = models.CharField(max_length=50)
    variant_name = models.CharField(max_length=100, blank=True)

    # Pricing (captured at time of order)
    unit_price = models.DecimalField(max_digits=10, decimal_places=2)
    quantity = models.IntegerField(validators=[MinValueValidator(1)])
    total_price = models.DecimalField(max_digits=10, decimal_places=2)

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = 'Order Item'
        verbose_name_plural = 'Order Items'

    def __str__(self):
        return f"{self.product_name} x {self.quantity}"

    def save(self, *args, **kwargs):
        # Calculate total price
        self.total_price = self.unit_price * self.quantity
        super().save(*args, **kwargs)
