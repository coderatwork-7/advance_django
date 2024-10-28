# documents.py
from django_elasticsearch_dsl.registries import registry
from django_elasticsearch_dsl import Document, fields
from elasticsearch_dsl import analyzer, tokenizer, Text


from .models import Product

ngram_tokenizer = tokenizer(
    'ngram_tokenizer',
    'ngram',
    min_gram=1,
    max_gram=2,
)

# Define your n-gram analyzer
ngram_analyzer = analyzer(
    'ngram_analyzer',
    tokenizer=ngram_tokenizer,
    filter=['lowercase']
)
@registry.register_document
class ProductDocuments(Document):
    title = fields.TextField(analyzer='standard')
    description = fields.TextField(analyzer='standard')
    title_suggest = fields.CompletionField(analyzer=ngram_analyzer)

    class Index:
        name = 'product_index'
    class Django:
        model = Product
        # fields = [
        #     'description',
        # ]

    def prepare_title_suggest(self, instance):
        return instance.description