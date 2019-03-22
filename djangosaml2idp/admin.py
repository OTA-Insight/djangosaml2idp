from django.contrib import admin

from .models import *

@admin.register(AgreementRecord)
class AgreementRecordAdmin(admin.ModelAdmin):
    list_display = ('user',
                    'sp_entity_id',
                    'created',
                    'modified')
