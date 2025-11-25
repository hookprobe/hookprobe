"""
Management command to seed sample merchandise data.
"""

from django.core.management.base import BaseCommand
from django.contrib.auth.models import User
from apps.merchandise.models import ProductCategory, Product, ProductVariant
from decimal import Decimal


class Command(BaseCommand):
    help = 'Seeds sample merchandise data (Homepod Toys, T-shirts, Stickers)'

    def handle(self, *args, **options):
        self.stdout.write('Seeding merchandise data...')

        # Get or create admin user
        admin_user = User.objects.filter(is_superuser=True).first()
        if not admin_user:
            self.stdout.write(self.style.WARNING('No admin user found. Creating default admin...'))
            admin_user = User.objects.create_superuser('admin', 'admin@hookprobe.com', 'admin')

        # Create categories
        self.stdout.write('Creating categories...')

        homepod_cat, _ = ProductCategory.objects.get_or_create(
            slug='homepod-toys',
            defaults={
                'name': 'Homepod Toys',
                'description': 'HookProbe-themed collectible toys and gadgets',
                'order': 1,
                'active': True
            }
        )

        tshirt_cat, _ = ProductCategory.objects.get_or_create(
            slug='t-shirts',
            defaults={
                'name': 'T-shirts',
                'description': 'HookProbe branded t-shirts for security enthusiasts',
                'order': 2,
                'active': True
            }
        )

        sticker_cat, _ = ProductCategory.objects.get_or_create(
            slug='stickers',
            defaults={
                'name': 'Stickers',
                'description': 'Show your support with HookProbe stickers',
                'order': 3,
                'active': True
            }
        )

        self.stdout.write(self.style.SUCCESS(f'✓ Created {ProductCategory.objects.count()} categories'))

        # Create Homepod Toys
        self.stdout.write('Creating Homepod Toys products...')

        Product.objects.get_or_create(
            slug='hookprobe-mini-sbc',
            defaults={
                'name': 'HookProbe Mini SBC Toy',
                'category': homepod_cat,
                'description': 'A miniature replica of the HookProbe SBC security appliance. Perfect for your desk!',
                'short_description': 'Miniature HookProbe SBC replica',
                'price': Decimal('29.99'),
                'compare_at_price': Decimal('39.99'),
                'sku': 'HP-TOY-001',
                'stock_quantity': 50,
                'weight': Decimal('0.15'),
                'dimensions': '5cm x 5cm x 2cm',
                'active': True,
                'featured': True,
                'created_by': admin_user
            }
        )

        Product.objects.get_or_create(
            slug='qsecbit-ai-figurine',
            defaults={
                'name': 'Qsecbit AI Figurine',
                'category': homepod_cat,
                'description': 'Limited edition Qsecbit AI mascot figurine. Represents the AI-powered threat detection system.',
                'short_description': 'Qsecbit AI mascot collectible',
                'price': Decimal('34.99'),
                'sku': 'HP-TOY-002',
                'stock_quantity': 30,
                'weight': Decimal('0.20'),
                'dimensions': '8cm x 4cm x 4cm',
                'active': True,
                'featured': False,
                'created_by': admin_user
            }
        )

        # Create T-shirts
        self.stdout.write('Creating T-shirt products...')

        tshirt, created = Product.objects.get_or_create(
            slug='hookprobe-classic-tee',
            defaults={
                'name': 'HookProbe Classic T-Shirt',
                'category': tshirt_cat,
                'description': 'Comfortable cotton t-shirt with the HookProbe logo. Available in multiple sizes.',
                'short_description': 'Classic HookProbe logo tee',
                'price': Decimal('24.99'),
                'sku': 'HP-TSH-001',
                'stock_quantity': 0,  # Variants will have stock
                'has_variants': True,
                'weight': Decimal('0.25'),
                'active': True,
                'featured': True,
                'created_by': admin_user
            }
        )

        if created:
            # Create size variants for t-shirt
            sizes = [
                ('S', 'Small', 20),
                ('M', 'Medium', 30),
                ('L', 'Large', 25),
                ('XL', 'Extra Large', 15),
            ]
            for size_code, size_name, stock in sizes:
                ProductVariant.objects.create(
                    product=tshirt,
                    name=size_name,
                    variant_type='Size',
                    sku=f'HP-TSH-001-{size_code}',
                    stock_quantity=stock,
                    active=True
                )

        Product.objects.get_or_create(
            slug='hookprobe-security-ops-tee',
            defaults={
                'name': 'HookProbe Security Ops T-Shirt',
                'category': tshirt_cat,
                'description': 'Black t-shirt with "Security Operations Center" text and HookProbe branding.',
                'short_description': 'SOC-themed t-shirt',
                'price': Decimal('27.99'),
                'sku': 'HP-TSH-002',
                'stock_quantity': 40,
                'weight': Decimal('0.25'),
                'active': True,
                'featured': False,
                'created_by': admin_user
            }
        )

        # Create Stickers
        self.stdout.write('Creating Sticker products...')

        Product.objects.get_or_create(
            slug='hookprobe-logo-sticker-pack',
            defaults={
                'name': 'HookProbe Logo Sticker Pack',
                'category': sticker_cat,
                'description': 'Pack of 5 vinyl HookProbe logo stickers. Waterproof and UV resistant.',
                'short_description': '5-pack vinyl logo stickers',
                'price': Decimal('4.99'),
                'sku': 'HP-STK-001',
                'stock_quantity': 200,
                'weight': Decimal('0.01'),
                'dimensions': '7.5cm x 7.5cm each',
                'active': True,
                'featured': True,
                'created_by': admin_user
            }
        )

        Product.objects.get_or_create(
            slug='qsecbit-ai-sticker',
            defaults={
                'name': 'Qsecbit AI Threat Detection Sticker',
                'category': sticker_cat,
                'description': 'Show your support for AI-powered security with this Qsecbit sticker.',
                'short_description': 'Qsecbit AI sticker',
                'price': Decimal('2.99'),
                'sku': 'HP-STK-002',
                'stock_quantity': 150,
                'weight': Decimal('0.01'),
                'dimensions': '10cm x 5cm',
                'active': True,
                'featured': False,
                'created_by': admin_user
            }
        )

        Product.objects.get_or_create(
            slug='hookprobe-pod-network-sticker-set',
            defaults={
                'name': 'POD Network Architecture Sticker Set',
                'category': sticker_cat,
                'description': 'Complete set of 9 stickers representing each HookProbe POD (001-009).',
                'short_description': 'POD architecture sticker set',
                'price': Decimal('9.99'),
                'compare_at_price': Decimal('14.99'),
                'sku': 'HP-STK-003',
                'stock_quantity': 80,
                'weight': Decimal('0.02'),
                'dimensions': '5cm x 5cm each',
                'active': True,
                'featured': False,
                'created_by': admin_user
            }
        )

        total_products = Product.objects.count()
        total_variants = ProductVariant.objects.count()

        self.stdout.write(self.style.SUCCESS(f'✓ Created {total_products} products'))
        self.stdout.write(self.style.SUCCESS(f'✓ Created {total_variants} product variants'))
        self.stdout.write(self.style.SUCCESS('✅ Merchandise data seeded successfully!'))
        self.stdout.write('')
        self.stdout.write('You can now access the Django admin to manage products:')
        self.stdout.write('  http://your-server/admin/merchandise/')
