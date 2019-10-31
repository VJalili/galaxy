"""
Contains the user interface in the Universe class
"""

import logging
from datetime import datetime, timedelta

from markupsafe import escape
from six.moves.urllib.parse import unquote
from sqlalchemy import or_
from sqlalchemy.orm.exc import NoResultFound

from galaxy import (
    util,
    web
)
from galaxy.managers import users
from galaxy.queue_worker import send_local_control_task
from galaxy.security.validate_user_input import (
    validate_email,
    validate_password,
    validate_publicname
)
from galaxy.web import _future_expose_api_anonymous_and_sessionless as expose_api_anonymous_and_sessionless
from galaxy.web import url_for
from galaxy.web.base.controller import (
    BaseUIController,
    CreatesApiKeysMixin,
    UsesFormDefinitionsMixin
)

log = logging.getLogger(__name__)


class User(BaseUIController, UsesFormDefinitionsMixin, CreatesApiKeysMixin):
    installed_len_files = None

    @web.expose
    def openid_auth( self, trans, **kwd ):
        '''Handles user request to access an OpenID provider'''
        if not trans.app.config.enable_openid:
            return trans.show_error_message( 'OpenID authentication is not enabled in this instance of Galaxy' )
        message = 'Unspecified failure authenticating via OpenID'
        auto_associate = util.string_as_bool( kwd.get( 'auto_associate', False ) )
        use_panels = util.string_as_bool( kwd.get( 'use_panels', False ) )
        consumer = trans.app.openid_manager.get_consumer( trans )
        openid_url = kwd.get('openid_url', '')
        openid_provider = kwd.get('openid_provider', '')
        if openid_url:
            openid_provider_obj = trans.app.openid_providers.new_provider_from_identifier( openid_url )
        elif openid_provider:
            openid_provider_obj = trans.app.openid_providers.get(openid_provider)
        else:
            message = 'An OpenID provider was not specified'
        redirect = kwd.get('redirect', '').strip()
        if not redirect:
            redirect = ' '
        if openid_provider_obj:
            process_url = trans.request.base.rstrip( '/' ) + url_for( controller='user', action='openid_process', redirect=redirect, openid_provider=openid_provider, auto_associate=auto_associate )  # None of these values can be empty, or else a verification error will occur
            request = None
            try:
                request = consumer.begin( openid_provider_obj.op_endpoint_url )
                if request is None:
                    message = 'No OpenID services are available at %s' % openid_provider_obj.op_endpoint_url
            except Exception as e:
                message = 'Failed to begin OpenID authentication: %s' % str( e )
            if request is not None:
                trans.app.openid_manager.add_sreg( trans, request, required=openid_provider_obj.sreg_required, optional=openid_provider_obj.sreg_optional )
                if request.shouldSendRedirect():
                    redirect_url = request.redirectURL(
                        trans.request.base, process_url )
                    trans.app.openid_manager.persist_session( trans, consumer )
                    return trans.response.send_redirect( redirect_url )
                else:
                    form = request.htmlMarkup( trans.request.base, process_url, form_tag_attrs={'id': 'openid_message', 'target': '_top'} )
                    trans.app.openid_manager.persist_session( trans, consumer )
                    return form
        return trans.response.send_redirect( url_for(controller='user',
                                                     action='login',
                                                     redirect=redirect,
                                                     use_panels=use_panels,
                                                     message=message,
                                                     status='error') )

    @web.expose
    def openid_process( self, trans, **kwd ):
        '''Handle's response from OpenID Providers'''
        if not trans.app.config.enable_openid:
            return trans.show_error_message( 'OpenID authentication is not enabled in this instance of Galaxy' )
        auto_associate = util.string_as_bool( kwd.get( 'auto_associate', False ) )
        action = 'login'
        if trans.user:
            action = 'openid_manage'
        if trans.app.config.support_url is not None:
            contact = '<a href="%s">support</a>' % trans.app.config.support_url
        else:
            contact = 'support'
        message = 'Verification failed for an unknown reason.  Please contact %s for assistance.' % ( contact )
        status = 'error'
        consumer = trans.app.openid_manager.get_consumer( trans )
        info = consumer.complete( kwd, trans.request.url )
        display_identifier = info.getDisplayIdentifier()
        redirect = kwd.get( 'redirect', '' ).strip()
        openid_provider = kwd.get( 'openid_provider', None )
        if info.status == trans.app.openid_manager.FAILURE and display_identifier:
            message = "Login via OpenID failed.  The technical reason for this follows, please include this message in your email if you need to %s to resolve this problem: %s" % ( contact, info.message )
            return trans.response.send_redirect( url_for( controller='user',
                                                          action=action,
                                                          use_panels=True,
                                                          redirect=redirect,
                                                          message=message,
                                                          status='error' ) )
        elif info.status == trans.app.openid_manager.SUCCESS:
            if info.endpoint.canonicalID:
                display_identifier = info.endpoint.canonicalID
            openid_provider_obj = trans.app.openid_providers.get( openid_provider )
            user_openid = trans.sa_session.query( trans.app.model.UserOpenID ).filter( trans.app.model.UserOpenID.table.c.openid == display_identifier ).first()
            if not openid_provider_obj and user_openid and user_openid.provider:
                openid_provider_obj = trans.app.openid_providers.get( user_openid.provider )
            if not openid_provider_obj:
                openid_provider_obj = trans.app.openid_providers.new_provider_from_identifier( display_identifier )
            if not user_openid:
                user_openid = trans.app.model.UserOpenID( session=trans.galaxy_session, openid=display_identifier )
            if not user_openid.user:
                user_openid.session = trans.galaxy_session
            if not user_openid.provider and openid_provider:
                user_openid.provider = openid_provider
            if trans.user:
                if user_openid.user and user_openid.user.id != trans.user.id:
                    message = "The OpenID <strong>%s</strong> is already associated with another Galaxy account, <strong>%s</strong>.  Please disassociate it from that account before attempting to associate it with a new account." % ( escape( display_identifier ), escape( user_openid.user.email ) )
                if not trans.user.active and trans.app.config.user_activation_on:  # Account activation is ON and the user is INACTIVE.
                    if ( trans.app.config.activation_grace_period != 0 ):  # grace period is ON
                        if self.is_outside_grace_period( trans, trans.user.create_time ):  # User is outside the grace period. Login is disabled and he will have the activation email resent.
                            message, status = self.resend_verification_email( trans, trans.user.email, trans.user.username )
                        else:  # User is within the grace period, let him log in.
                            pass
                    else:  # Grace period is off. Login is disabled and user will have the activation email resent.
                        message, status = self.resend_verification_email( trans, trans.user.email, trans.user.username )
                elif not user_openid.user or user_openid.user == trans.user:
                    if openid_provider_obj.id:
                        user_openid.provider = openid_provider_obj.id
                    user_openid.session = trans.galaxy_session
                    if not openid_provider_obj.never_associate_with_user:
                        if not auto_associate and ( user_openid.user and user_openid.user.id == trans.user.id ):
                            message = "The OpenID <strong>%s</strong> is already associated with your Galaxy account, <strong>%s</strong>." % ( escape( display_identifier ), escape( trans.user.email ) )
                            status = "warning"
                        else:
                            message = "The OpenID <strong>%s</strong> has been associated with your Galaxy account, <strong>%s</strong>." % ( escape( display_identifier ), escape( trans.user.email ) )
                            status = "done"
                        user_openid.user = trans.user
                        trans.sa_session.add( user_openid )
                        trans.sa_session.flush()
                        trans.log_event( "User associated OpenID: %s" % display_identifier )
                    else:
                        trans.log_event("Created role for auto-registered user.")
            if auto_create_groups:
                # only create a group if not existing yet
                try:
                    group = self.sa_session.query(trans.app.model.Group).filter(
                        trans.app.model.Group.table.c.name == role_name).first()
                except NoResultFound:
                    group = self.model.Group(name=role_name)
                    self.sa_session.add(group)
                trans.app.security_agent.associate_user_group(user, group)

            if auto_assign_roles_to_groups_only and group and role:
                trans.log_event("Assigning role to group only")
                trans.app.security_agent.associate_group_role(group, role)
            elif not auto_assign_roles_to_groups_only and role:
                trans.log_event("Assigning role to newly created user")
                trans.app.security_agent.associate_user_role(user, role)

    def __autoregistration(self, trans, login, password, status, kwd, no_password_check=False, cntrller=None):
        """
        Does the autoregistration if enabled. Returns a message
        """
        autoreg = trans.app.auth_manager.check_auto_registration(trans, login, password, no_password_check=no_password_check)
        user = None
        success = False
        if autoreg["auto_reg"]:
            kwd["email"] = autoreg["email"]
            kwd["username"] = autoreg["username"]
            message = " ".join([validate_email(trans, kwd["email"], allow_empty=True),
                                validate_publicname(trans, kwd["username"])]).rstrip()
            if not message:
                message, status, user, success = self.__register(trans, **kwd)
                if success:
                    # The handle_user_login() method has a call to the history_set_default_permissions() method
                    # (needed when logging in with a history), user needs to have default permissions set before logging in
                    if not trans.user_is_admin:
                        trans.handle_user_login(user)
                        trans.log_event("User (auto) created a new account")
                        trans.log_event("User logged in")
                    if "attributes" in autoreg and "roles" in autoreg["attributes"]:
                        self.__handle_role_and_group_auto_creation(
                            trans, user, autoreg["attributes"]["roles"],
                            auto_create_groups=autoreg["auto_create_groups"],
                            auto_create_roles=autoreg["auto_create_roles"],
                            auto_assign_roles_to_groups_only=autoreg["auto_assign_roles_to_groups_only"])
                else:
                    message = "Auto-registration failed, contact your local Galaxy administrator. %s" % message
            else:
                message = "Auto-registration failed, contact your local Galaxy administrator. %s" % message
        else:
            message = "No such user or invalid password."
        return message, status, user, success

    @expose_api_anonymous_and_sessionless
    def login(self, trans, payload={}, **kwd):
        return self.__validate_login(trans, payload, **kwd)

    def __validate_login(self, trans, payload={}, **kwd):
        '''Handle Galaxy Log in'''
        if not payload:
            payload = kwd
        message = trans.check_csrf_token(payload)
        if message:
            return self.message_exception(trans, message)
        login = payload.get("login")
        password = payload.get("password")
        redirect = payload.get("redirect")
        status = None
        if not login or not password:
            return self.message_exception(trans, "Please specify a username and password.")
        user = trans.sa_session.query(trans.app.model.User).filter(or_(
            trans.app.model.User.table.c.email == login,
            trans.app.model.User.table.c.username == login
        )).first()
        log.debug("trans.app.config.auth_config_file: %s" % trans.app.config.auth_config_file)
        if user is None:
            message, status, user, success = self.__autoregistration(trans, login, password, status, kwd)
            if not success:
                return self.message_exception(trans, message)
        elif user.deleted:
            message = "This account has been marked deleted, contact your local Galaxy administrator to restore the account."
            if trans.app.config.error_email_to is not None:
                message += " Contact: %s." % trans.app.config.error_email_to
            return self.message_exception(trans, message, sanitize=False)
        elif user.external:
            message = "This account was created for use with an external authentication method, contact your local Galaxy administrator to activate it."
            if trans.app.config.error_email_to is not None:
                message += " Contact: %s." % trans.app.config.error_email_to
            return self.message_exception(trans, message, sanitize=False)
        elif not trans.app.auth_manager.check_password(user, password):
            return self.message_exception(trans, "Invalid password.")
        elif trans.app.config.user_activation_on and not user.active:  # activation is ON and the user is INACTIVE
            if (trans.app.config.activation_grace_period != 0):  # grace period is ON
                if self.is_outside_grace_period(trans, user.create_time):  # User is outside the grace period. Login is disabled and he will have the activation email resent.
                    message, status = self.resend_activation_email(trans, user.email, user.username)
                    return self.message_exception(trans, message, sanitize=False)
                else:  # User is within the grace period, let him log in.
                    trans.handle_user_login(user)
                    trans.log_event("User logged in")
            else:  # Grace period is off. Login is disabled and user will have the activation email resent.
                message, status = self.resend_activation_email(trans, user.email, user.username)
                return self.message_exception(trans, message, sanitize=False)
        else:  # activation is OFF
            pw_expires = trans.app.config.password_expiration_period
            if pw_expires and user.last_password_change < datetime.today() - pw_expires:
                # Password is expired, we don't log them in.
                return {"message": "Your password has expired. Please reset or change it to access Galaxy.", "status": "warning", "expired_user": trans.security.encode_id(user.id)}
            trans.handle_user_login(user)
            trans.log_event("User logged in")
            if pw_expires and user.last_password_change < datetime.today() - timedelta(days=pw_expires.days / 10):
                # If password is about to expire, modify message to state that.
                expiredate = datetime.today() - user.last_password_change + pw_expires
                return {"message": "Your password will expire in %s day(s)." % expiredate.days, "status": "warning"}
        return {"message": "Success.", "redirect": self.__get_redirect_url(redirect)}

    @web.expose
    def resend_verification(self, trans):
        """
        Exposed function for use outside of the class. E.g. when user click on the resend link in the masthead.
        """
        message, status = self.resend_activation_email(trans, None, None)
        if status == 'done':
            return trans.show_ok_message(message)
        else:
            return trans.show_error_message(message)

    def resend_activation_email(self, trans, email, username):
        """
        Function resends the verification email in case user wants to log in with an inactive account or he clicks the resend link.
        """
        if email is None:  # User is coming from outside registration form, load email from trans
            email = trans.user.email
        if username is None:  # User is coming from outside registration form, load email from trans
            username = trans.user.username
        is_activation_sent = self.user_manager.send_activation_email(trans, email, username)
        if is_activation_sent:
            message = 'This account has not been activated yet. The activation link has been sent again. Please check your email address <b>%s</b> including the spam/trash folder.<br><a target="_top" href="%s">Return to the home page</a>.' % (escape(email), url_for('/'))
            status = 'error'
        else:
            message = 'This account has not been activated yet but we are unable to send the activation link. Please contact your local Galaxy administrator.<br><a target="_top" href="%s">Return to the home page</a>.' % url_for('/')
            status = 'error'
            if trans.app.config.error_email_to is not None:
                message += '<br>Error contact: %s' % trans.app.config.error_email_to
        return message, status

    def is_outside_grace_period(self, trans, create_time):
        """
        Function checks whether the user is outside the config-defined grace period for inactive accounts.
        """
        #  Activation is forced and the user is not active yet. Check the grace period.
        activation_grace_period = trans.app.config.activation_grace_period
        delta = timedelta(hours=int(activation_grace_period))
        time_difference = datetime.utcnow() - create_time
        return (time_difference > delta or activation_grace_period == 0)

    @web.expose
    def logout(self, trans, logout_all=False, **kwd):
        message = trans.check_csrf_token(kwd)
        if message:
            return self.message_exception(trans, message)
        if trans.user:
            # Queue a quota recalculation (async) task -- this takes a
            # while sometimes, so we don't want to block on logout.
            send_local_control_task(trans.app,
                                    "recalculate_user_disk_usage",
                                    {"user_id": trans.security.encode_id(trans.user.id)})
        # Since logging an event requires a session, we'll log prior to ending the session
        trans.log_event("User logged out")
        trans.handle_user_logout(logout_all=logout_all)

    @expose_api_anonymous_and_sessionless
    def create(self, trans, payload={}, **kwd):
        if not payload:
            payload = kwd
        message = trans.check_csrf_token(payload)
        if message:
            return self.message_exception(trans, message)
        user, message = self.user_manager.register(trans, **payload)
        if message:
            return self.message_exception(trans, message, sanitize=False)
        elif user and not trans.user_is_admin:
            trans.handle_user_login(user)
            trans.log_event("User created a new account")
            trans.log_event("User logged in")
        return {"message": "Success."}

    @web.expose
    def activate(self, trans, **kwd):
        """
        Check whether token fits the user and then activate the user's account.
        """
        params = util.Params(kwd, sanitize=False)
        email = params.get('email', None)
        if email is not None:
            email = unquote(email)
        activation_token = params.get('activation_token', None)

        if email is None or activation_token is None:
            #  We don't have the email or activation_token, show error.
            return trans.show_error_message("You are using an invalid activation link. Try to log in and we will send you a new activation email. <br><a href='%s'>Go to login page.</a>") % web.url_for(controller="root", action="index")
        else:
            # Find the user
            user = trans.sa_session.query(trans.app.model.User).filter(trans.app.model.User.table.c.email == email).first()
            if not user:
                # Probably wrong email address
                return trans.show_error_message("You are using an invalid activation link. Try to log in and we will send you a new activation email. <br><a href='%s'>Go to login page.</a>") % web.url_for(controller="root", action="index")
            # If the user is active already don't try to activate
            if user.active is True:
                return trans.show_ok_message("Your account is already active. Nothing has changed. <br><a href='%s'>Go to login page.</a>") % web.url_for(controller='root', action='index')
            if user.activation_token == activation_token:
                user.activation_token = None
                user.active = True
                trans.sa_session.add(user)
                trans.sa_session.flush()
                return trans.show_ok_message("Your account has been successfully activated! <br><a href='%s'>Go to login page.</a>") % web.url_for(controller='root', action='index')
            else:
                #  Tokens don't match. Activation is denied.
                return trans.show_error_message("You are using an invalid activation link. Try to log in and we will send you a new activation email. <br><a href='%s'>Go to login page.</a>") % web.url_for(controller='root', action='index')
        return

    @expose_api_anonymous_and_sessionless
    def change_password(self, trans, payload={}, **kwd):
        """
        Allows to change own password.

        :type   payload: dict
        :param  payload: dictionary structure containing:
            * id:               encoded user id
            * current:          current user password
            * token:            temporary token to change password (instead of id and current)
            * password:         new password
            * confirm:          new password (confirmation)
        """
        user, message = self.user_manager.change_password(trans, **payload)
        if user is None:
            return self.message_exception(trans, message)
        trans.handle_user_login(user)
        return {"message": "Password has been changed."}

    @expose_api_anonymous_and_sessionless
    def reset_password(self, trans, payload={}, **kwd):
        """Reset the user's password. Send an email with token that allows a password change."""
        message = self.user_manager.send_reset_email(trans, payload)
        if message:
            return self.message_exception(trans, message)
        return {"message": "Reset link has been sent to your email."}

    def __validate(self, trans, email, password, confirm, username):
        message = "\n".join([validate_email(trans, email),
                             validate_password(trans, password, confirm),
                             validate_publicname(trans, username)]).rstrip()
        return message

    def __get_redirect_url(self, redirect):
        if not redirect or redirect == "None":
            return None
        root_url = url_for('/', qualified=True)
        # compare urls, to prevent a redirect from pointing (directly) outside of galaxy
        # or to enter a logout/login loop
        if not util.compare_urls(root_url, redirect, compare_path=False) or util.compare_urls(url_for(controller='user', action='logout', qualified=True), redirect):
            log.warning('Redirect URL is outside of Galaxy, will redirect to Galaxy root instead: %s', redirect)
            redirect = root_url
        elif util.compare_urls(url_for(controller='user', action='logout', qualified=True), redirect):
            redirect = root_url
        return redirect
