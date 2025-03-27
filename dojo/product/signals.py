from auditlog.models import LogEntry
from django.conf import settings
from django.contrib.contenttypes.models import ContentType
from django.db.models.signals import post_delete, post_save
from django.dispatch import receiver
from django.urls import reverse
from django.utils.translation import gettext as _

from dojo.models import Product
from dojo.notifications.helper import create_notification

from dojo.models import Engagement, Test, Test_Type


@receiver(post_save, sender=Product)
def product_post_save(sender, instance, created, **kwargs):
    if created:
        create_notification(event="product_added",
                            title=instance.name,
                            product=instance,
                            url=reverse("view_product", args=(instance.id,)),
                            url_api=reverse("product-detail", args=(instance.id,)),
                        )


@receiver(post_delete, sender=Product)
def product_post_delete(sender, instance, **kwargs):
    if settings.ENABLE_AUDITLOG:
        le = LogEntry.objects.get(
            action=LogEntry.Action.DELETE,
            content_type=ContentType.objects.get(app_label="dojo", model="product"),
            object_id=instance.id,
        )
        description = _('The product "%(name)s" was deleted by %(user)s') % {
                            "name": instance.name, "user": le.actor}
    else:
        description = _('The product "%(name)s" was deleted') % {"name": instance.name}
    create_notification(event="product_deleted",  # template does not exists, it will default to "other" but this event name needs to stay because of unit testing
                        title=_("Deletion of %(name)s") % {"name": instance.name},
                        description=description,
                        url=reverse("product"),
                        icon="exclamation-triangle")

# @receiver(post_save, sender=Engagement)
# def create_default_scan_for_engagement(sender, instance, created, **kwargs):
#     """
#     Signal handler to automatically create a default scan/test
#     whenever a new engagement is created
#     """
#     print("HELLO SIGNAL 1")
#     print(type(instance))
#     print("INSTANCE ", instance.product.prod_type)

#     if created:  # Only run when the engagement is first created
#         try:
#             engagement_count = Engagement.objects.filter(product=instance.product).count()

#             if engagement_count == 1:
#                 default_test_type = Test_Type.objects.get(name="Philips RMM Scan")
#                 print("HELLO SIGNAL 2")
#                 print("DEFAULT TEST TYPE", default_test_type)
                
#                 test = Test(
#                     engagement=instance,
#                     test_type=default_test_type,
#                     target_start=instance.target_start,
#                     target_end=instance.target_end,
#                 )
#                 test.save()

#                 import logging
#                 logger = logging.getLogger(__name__)
#                 logger.debug(f"Default scan created for engagement {instance.id}")
            
#         except Test_Type.DoesNotExist:
#             import logging
#             logger = logging.getLogger(__name__)
#             logger.error("Default test type not found - could not create default scan")
#         except Exception as e:
#             # Catch any other exceptions
#             import logging
#             logger = logging.getLogger(__name__)
#             logger.error(f"Error creating default scan: {str(e)}")