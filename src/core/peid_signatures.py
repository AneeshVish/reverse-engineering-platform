# Minimal PEiD signature database for demo purposes
# In practice, use a full PEiD userdb.txt or a more complete signature set
PEID_SIGNATURES = [
    {
        'name': 'UPX',
        'ep_only': True,
        'sig': b'UPX0',
    },
    {
        'name': 'ASPack',
        'ep_only': False,
        'sig': b'.aspack',
    },
    {
        'name': 'FSG',
        'ep_only': False,
        'sig': b'.FSG!',
    },
    # Add more signatures as needed
]
