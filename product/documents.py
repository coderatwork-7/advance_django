# documents.py
from django_elasticsearch_dsl.registries import registry
from django_elasticsearch_dsl import Document, fields

from .models import Product

@registry.register_document
class ProductDocuments(Document):
    title_suggest = fields.CompletionField()

    class Index:
        name = 'product_index'

    class Django:
        model = Product
        fields = [
            'title',
            'description',
        ]

    def prepare_title_suggest(self, instance):
        return instance.title