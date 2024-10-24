from django.core.management.base import BaseCommand
from faker import Faker
from product.models import Product  # Replace with your model
import random

class Command(BaseCommand):
    help = 'Generate fake data'

    def handle(self, *args, **kwargs):
        fake = Faker()
        num_records = 100000

        for _ in range(num_records):
            title = fake.sentence(nb_words=3)  
            description = fake.text(max_nb_chars=255)  
            
            Product.objects.create(
                title=title,
                description=description,
            )

        self.stdout.write(self.style.SUCCESS(f'Successfully created {num_records} fake products.'))