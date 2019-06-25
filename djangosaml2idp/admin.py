from django.contrib import admin

from .models import AgreementRecord


@admin.register(AgreementRecord)
class AgreementRecordAdmin(admin.ModelAdmin):
    list_display = ('user',
                    'sp_entity_id',
                    'created')
    readonly_fields = ('attrs', 'sp_entity_id', 'user')
