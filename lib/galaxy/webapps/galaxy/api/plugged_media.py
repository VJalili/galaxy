"""
API operations on Plugged Media.

.. see also:: :class:`galaxy.model.PluggedMedia`
"""
import logging

from galaxy import exceptions
from galaxy import web
from galaxy.managers import (
    datasets,
    hdas,
    plugged_media,
    users
)
from galaxy.util import (
    string_as_bool
)
from galaxy.web import (
    _future_expose_api as expose_api)

from galaxy.web.base.controller import BaseAPIController

log = logging.getLogger(__name__)


class PluggedMediaController(BaseAPIController):
    """
    RESTful controller for interactions with plugged media.
    """

    def __init__(self, app):
        super(PluggedMediaController, self).__init__(app)
        self.user_manager = users.UserManager(app)
        self.plugged_media_manager = plugged_media.PluggedMediaManager(app)
        self.plugged_media_serializer = plugged_media.PluggedMediaSerializer(app)
        self.hda_manager = hdas.HDAManager(app)
        self.dataset_manager = datasets.DatasetManager(app)

    @web.expose_api_anonymous
    def index(self, trans, **kwd):
        """
        GET /api/plugged_media: returns a list of installed plugged media
        """
        user = self.user_manager.current_user(trans)
        if self.user_manager.is_anonymous(user):
            # an anonymous user is not expected to have installed a plugged media.
            return []
        rtv = []
        for pm in user.plugged_media:
            rtv.append(self.plugged_media_serializer.serialize_to_view(
                pm, user=trans.user, trans=trans, **self._parse_serialization_params(kwd, 'summary')))
        return rtv

    @web.expose_api_anonymous
    def create(self, trans, payload, **kwd):
        """
        create(self, trans, payload, **kwd)
        * POST /api/plugged_media:
            Creates a new plugged media.

        :type  trans: galaxy.web.framework.webapp.GalaxyWebTransaction
        :param trans: Galaxy web transaction.

        :type  payload: dict
        :param payload: A dictionary structure containing the following keys:
            - order: A key which defines the hierarchical relation between this and other plugged media defined
            by the user.
            - category: is the type of this plugged media, its value is a key from `categories` bunch defined in the
            `PluggedMedia` class.
            - path: a path in the plugged media to be used (e.g., AWS S3 Bucket name).
            - order : Sets the order of this plugged media, it is an integer specifying the order in
            which a plugged media should be tried to persiste a dataset on. Order is relative to the default
            Galaxy instance storage, which has a reserved order 0, where plugged media with positive and negative
            order are tried prior and posterior to the default storage respectively. For instance, considering 3
            plugged media, PM_1, PM_2, and PM_3 with the orders 2, 1, and -1 respectively; Galaxy tries the these
            plugged media in the following order: PM_1, PM_2, Default, PM_3.
            - credentials (Optional): It is a JSON object containing required credentials to access the plugged media
             (e.g., access and secret key for an AWS S3 bucket).
            - quota (Optional): Disk quota, a limit that sets maximum data storage limit on this plugged media.
            - usage (Optional): Sets the size of data persisted by Galaxy in this plugged media.
        :rtype: dict
        :return: The newly created plugged media.
        """
        if not isinstance(payload, dict):
            trans.response.status = 400
            return "Invalid payload data type. The payload is expected to be a dictionary," \
                   " but received data of type '%s'." % str(type(payload))

        missing_arguments = []
        order = payload.get("order")
        if order is None:
            missing_arguments.append("order")
        try:
            order = int(order)
        except ValueError:
            return 'Expect an integer value for `order` argument, but received: `{}`.'.format(order)
        category = payload.get("category")
        if category is None:
            missing_arguments.append("category")
        path = payload.get("path")
        if path is None:
            missing_arguments.append("path")
        if len(missing_arguments) > 0:
            trans.response.status = 400
            return "The following required arguments are missing in the payload: %s" % missing_arguments
        if order == 0:
            return "The order `0` is reserved for default storage, choose a higher/lower order."
        purgeable = string_as_bool(payload.get("purgeable", True))

        try:
            quota = float(payload.get("quota", "0.0"))
        except ValueError:
            return "Expect a float number for the `quota` attribute, but received `{}`.".format(payload.get("quota"))
        try:
            usage = float(payload.get("usage", "0.0"))
        except ValueError:
            return "Expect a float number for the `usage` attribute, but received `{}`.".format(payload.get("usage"))

        encoded_authz_id = payload.get("authz_id", None)
        if encoded_authz_id is None:
            missing_arguments.append("authz_id")

        try:
            authz_id = self.decode_id(encoded_authz_id)
        except exceptions.MalformedId as e:
            return "Invalid authz ID. {}".format(e)

        try:
            trans.app.authnz_manager.can_user_assume_authz(trans, authz_id)
        except Exception:
            return "Invalid or inaccessible authorization record with given id."

        try:
            new_plugged_media = self.plugged_media_manager.create(
                user_id=trans.user.id,
                order=order,
                category=category,
                path=path,
                authz_id=authz_id,
                quota=quota,
                usage=usage,
                purgeable=purgeable)
            view = self.plugged_media_serializer.serialize_to_view(
                new_plugged_media, user=trans.user, trans=trans, **self._parse_serialization_params(kwd, 'summary'))
            # Do not use integer response codes (e.g., 200), as they are not accepted by the
            # 'wsgi_status' function in lib/galaxy/web/framework/base.py
            trans.response.status = '200 OK'
            log.debug('Created a new plugged media of type `%s` for the user id `%s` ', category, str(trans.user.id))
            return view
        except ValueError as e:
            log.debug('An error occurred while creating a plugged media. ' + str(e))
            trans.response.status = '400 Bad Request'
        except Exception as e:
            log.exception('An unexpected error has occurred while responding to the '
                          'create request of the plugged media API. ' + str(e))
            # Do not use integer response code (see above).
            trans.response.status = '500 Internal Server Error'
        return []

    @expose_api
    def delete(self, trans, id, **kwd):
        """
        delete(self, trans, id, **kwd)
        * DELETE /api/plugged_media/{id}
            Deletes the plugged media with the given ID, also deletes all the associated datasets and HDAs.

        :type  trans: galaxy.web.framework.webapp.GalaxyWebTransaction
        :param trans: Galaxy web transaction.

        :type id: string
        :param id: The encoded ID of the plugged media to be deleted.

        :type kwd: dict
        :param kwd: (optional) dictionary structure containing extra parameters (e.g., `purge`).

        :rtype: dict
        :return: The deleted or purged plugged media.
        """
        try:
            plugged_media = self.plugged_media_manager.get_owned(self.decode_id(id), trans.user)
            payload = kwd.get('payload', None)
            purge = False if payload is None else string_as_bool(payload.get('purge', False))
            if purge:
                self.plugged_media_manager.purge(plugged_media)
            else:
                self.plugged_media_manager.delete(plugged_media)
            return self.plugged_media_serializer.serialize_to_view(
                plugged_media, user=trans.user, trans=trans, **self._parse_serialization_params(kwd, 'summary'))
        except exceptions.ObjectNotFound:
            trans.response.status = '404 Not Found'
            msg = 'The plugged media with ID `{}` does not exist.'.format(str(id))
            log.debug(msg)
        except exceptions.ConfigDoesNotAllowException as e:
            trans.response.status = '403 Forbidden'
            msg = str(e)
            log.debug(msg)
        except AttributeError as e:
            trans.response.status = '500 Internal Server Error'
            msg = 'An unexpected error has occurred while deleting/purging a plugged media in response to the ' \
                  'related API call. Maybe an inappropriate database manipulation. ' + str(e)
            log.error(msg)
        except Exception as e:
            trans.response.status = '500 Internal Server Error'
            msg = 'An unexpected error has occurred while deleting/purging a plugged media in response to the ' \
                  'related API call. ' + str(e)
            log.error(msg)
        return msg
