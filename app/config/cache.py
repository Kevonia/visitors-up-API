# cache.py
from aiocache import caches

# Configure aiocache
def setup_cache():
    caches.set_config({
        'default': {
            'cache': "aiocache.SimpleMemoryCache",  # In-memory cache
            'serializer': {
                'class': "aiocache.serializers.JsonSerializer"  # Use JSON for serialization
            }
        }
    })

# Get the default cache
async def get_cache():
    return caches.get('default')