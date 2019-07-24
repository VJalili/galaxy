"""
Manager and Serializer for plugged media.
"""

import logging

from galaxy import exceptions
from galaxy import model
from galaxy.managers import (
    base,
    datasets,
    deletable,
    hdas,
    sharable
)

log = logging.getLogger(__name__)


class PluggedMediaManager(sharable.SharableModelManager, deletable.PurgableManagerMixin):

    model_class = model.PluggedMedia
    foreign_key_name = 'plugged_media'

    def __init__(self, app, *args, **kwargs):
        super(PluggedMediaManager, self).__init__(app, *args, **kwargs)
        self.hda_manager = hdas.HDAManager(app)
        self.dataset_manager = datasets.DatasetManager(app)

    def delete(self, plugged_media, **kwargs):
        """
        Deletes the given plugged media by taking the following steps:
        (1) marks the plugged media `deleted` in the database (i.e., setting
        the `deleted` attribute to True);
        (2) marks `deleted` all the datasets persisted on the plugged media;
        (3) marks `deleted` all the PluggedMedia-Dataset associations.
        :param plugged_media: The plugged media to be deleted.
        :type plugged_media: galaxy.model.PluggedMedia
        :return: returns the deleted plugged media.
        """
        super(PluggedMediaManager, self).delete(plugged_media, kwargs)
        for assoc in plugged_media.data_association:
            self.hda_manager.delete(assoc, kwargs)
            self.dataset_manager.delete(assoc.dataset, kwargs)
            super(PluggedMediaManager, self).delete(assoc, kwargs)
        self.session().flush()
        return plugged_media

    def undelete(self, plugged_media, **kwargs):
        """
        Un-deletes the given plugged media by taking the following steps:
        (1) marks the plugged media `un-deleted` in the database (i.e., setting
        the `deleted` attribute to False);
        (2) marks `un-deleted` all the datasets persisted on the plugged media;
        (3) marks `un-deleted` all the PluggedMedia-Dataset associations.
        :param plugged_media: The plugged media to be deleted.
        :type plugged_media: galaxy.model.PluggedMedia
        :return: returns the deleted plugged media.
        """
        super(PluggedMediaManager, self).undelete(plugged_media, kwargs)
        for assoc in plugged_media.data_association:
            self.hda_manager.delete(assoc, kwargs)
            self.dataset_manager.delete(assoc.dataset, kwargs)
            super(PluggedMediaManager, self).undelete(assoc, kwargs)
        self.session().flush()
        return plugged_media

    def purge(self, plugged_media, **kwargs):
        """
        Purges a plugged media by taking the following steps:
        (1) marks the plugged media `purged` in the database;
        (2) deletes all the datasets persisted on the plugged media;
        (3) marks all the HDAs associated with the deleted datasets as purged.
        This operation does NOT `delete` the plugged media physically
        (e.g., it does not delete a S3 bucket), because the plugged media
        (e.g., a S3 bucket) may contain data other than those loaded
        or mounted on Galaxy which deleting the media (e.g., deleting
        a S3 bucket) will result in unexpected file deletes.
        :param plugged_media: The media to be purged.
        :type: plugged_media: galaxy.model.PluggedMedia
        :return: returns the purged plugged media.
        """
        if not plugged_media.is_purgeable():
            raise exceptions.ConfigDoesNotAllowException(
                "The plugged media (ID: `{}`; category: `{}`) is not purgeable; because {}".format(
                    plugged_media.id, plugged_media.category,
                    "it's purgeable attribute is set to `False`." if plugged_media.purgeable is False
                    else "it contains at least one dataset which is not purgeable."))
        for i, assoc in enumerate(plugged_media.data_association):
            for hda in assoc.dataset.history_associations:
                self.hda_manager.purge(hda)
            self.dataset_manager.purge(assoc.dataset, plugged_media=plugged_media)
            plugged_media.data_association[i].purged = True
        plugged_media.purged = True
        self.session().flush()
        return plugged_media


class PluggedMediaSerializer(sharable.SharableModelSerializer, deletable.PurgableSerializerMixin):
    """
    Interface/service object for serializing plugged media into dictionaries.
    """
    model_manager_class = PluggedMediaManager

    def __init__(self, app, **kwargs):
        super(PluggedMediaSerializer, self).__init__(app, **kwargs)
        self.plugged_media_manager = self.manager

        self.default_view = 'summary'
        self.add_view('summary', [
            'id',
            'model_class',
            'user_id',
            'create_time',
            'update_time',
            'usage',
            'order',
            'quota',
            'category',
            'path',
            'deleted',
            'purged',
            'purgeable'
        ])

    def add_serializers(self):
        super(PluggedMediaSerializer, self).add_serializers()
        deletable.PurgableSerializerMixin.add_serializers(self)

        # Arguments of the following lambda functions:
        # i  : an instance of galaxy.model.PluggedMedia.
        # k  : serialized dictionary key (e.g., 'model_class', 'order', 'category', and 'path').
        # **c: a dictionary containing 'trans' and 'user' objects.
        self.serializers.update({
            'id'         : lambda i, k, **c: self.app.security.encode_id(i.id),
            'model_class': lambda *a, **c: 'PluggedMedia',
            'user_id'    : lambda i, k, **c: self.app.security.encode_id(i.user_id),
            'usage'      : lambda i, k, **c: str(i.usage),
            'order'      : lambda i, k, **c: i.order,
            'quota'      : lambda i, k, **c: str(i.quota),
            'category'   : lambda i, k, **c: i.category,
            'path'       : lambda i, k, **c: i.path,
            'deleted'    : lambda i, k, **c: i.deleted,
            'purged'     : lambda i, k, **c: i.purged,
            'purgeable'  : lambda i, k, **c: i.purgeable
        })


class PluggedMediaDeserializer(sharable.SharableModelDeserializer, deletable.PurgableDeserializerMixin):

    model_manager_class = PluggedMediaManager

    def add_deserializers(self):
        super(PluggedMediaDeserializer, self).add_deserializers()
        self.deserializers.update({
            'path': self.default_deserializer,
            'order': self.default_deserializer,
            'quota': self.default_deserializer,
            'authz_id': self.deserialize_and_validate_authz_id
        })

    def deserialize_and_validate_authz_id(self, item, key, val, **context):
        try:
            decoded_authz_id = self.app.security.decode_id(val)
        except Exception:
            log.debug("cannot decode authz_id `" + str(val) + "`")
            raise exceptions.MalformedId("Invalid `authz_id` {}!".format(val))

        trans = context.get("trans")
        if trans is None:
            log.debug("Not found expected `trans` when deserializing PluggedMedia.")
            raise exceptions.InternalServerError

        try:
            trans.app.authnz_manager.can_user_assume_authz(trans, decoded_authz_id)
        except Exception as e:
            raise e

        return decoded_authz_id
