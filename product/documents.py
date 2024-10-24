# documents.py
from django_elasticsearch_dsl import Document
from django_elasticsearch_dsl.registries import registry
from .models import Product

@registry.register_document
class ProductDocuments(Document):
    class Index:
        name = 'product_index'  

    class Django:
        model = Product  
        fields = ['id', 'title', 'description']


