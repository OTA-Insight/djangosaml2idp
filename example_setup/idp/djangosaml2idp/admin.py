from django.contrib import admin
from .models import ServiceProvider


@admin.register(ServiceProvider)
class ServiceProviderAdmin(admin.ModelAdmin):
    list_filter = ['active', ]
    list_display = ['pretty_name', 'entity_id', 'active', 'description']
    readonly_fields = ('dt_created', 'dt_updated')

    fieldsets = (
        ('Identification', {
            'fields': ('entity_id', 'pretty_name', 'description', 'metadata')
        }),
        ('Configuration', {
            'fields': ('active', '_processor', '_attribute_mapping', '_nameid_field', 'sign_response', 'sign_assertion', 'signing_algorithm', 'digest_algorithm'),
        }),
        (None, {
            'fields': ('dt_created', 'dt_updated')
        })
    )

    # TODO: validation / cleaning