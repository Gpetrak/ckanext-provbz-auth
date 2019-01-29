# -*- coding: utf8 -*-
# -*- coding: utf8 -*-
'''
Repoze.who plugin for ckanext-provbz-auth
'''

import logging
import requests
from urlparse import urlparse, urlunparse

from requests import Response
from webob import Request, Response
from zope.interface import implements

from repoze.who.interfaces import IIdentifier, IChallenger

from ckan.lib.helpers import url_for
import ckan.model as model


log = logging.getLogger("ckanext.provbzauth")

OP_NOT_EMPTY = 'not_empty'
OP_EQUALS = 'equals'


def make_identification_plugin(**kwargs):
    log.info("Creating ProvBzIdentifierPlugin...")

    return ProvBzIdentifierPlugin(**kwargs)


class ProvBzIdentifierPlugin(object):
    implements(IChallenger, IIdentifier)

    def is_active_session(self, env):

        val = env.get(self.check_auth_key, '')

        if self.check_auth_op == OP_NOT_EMPTY:
            return bool(val.strip())
        elif self.check_auth_op == OP_EQUALS:
            return val == self.check_auth_value
        else:
            return False


    def __init__(self, eppn, authtype, **kwargs):
        """
        Parameters here contain just names of the environment attributes defined
        in who.ini, not their values.
        """

        log.info("Initting ProvBzIdentifierPlugin...")

        self.check_auth_key = kwargs['check_auth_key']
        self.check_auth_op = kwargs['check_auth_op']
        self.check_auth_value = kwargs['check_auth_value'] if 'check_auth_value' in kwargs else None

        self.eppn = eppn
        self.auth_type = authtype

        self.pm_url = kwargs.get('pm_url')
        self.pm_user = kwargs.get('pm_user')
        self.pm_pw = kwargs.get('pm_pw')

        ok = True

        if self.check_auth_op not in (OP_NOT_EMPTY, OP_EQUALS):
            log.warning('Check auth operator not valid. Auth will not work.')
            ok = False

        if self.check_auth_key is None:
            log.warning('Check auth key not set in who.ini. Auth will not work.')
            ok = False

        if self.check_auth_op == OP_EQUALS and self.check_auth_value is None:
            log.warning('Check auth values not set in who.ini. Auth will not work.')
            ok = False

        if ok:
            if self.check_auth_op == OP_EQUALS:
                log.info('Authentication will be identified by %s = %s', self.check_auth_key, self.check_auth_value)
            elif self.check_auth_op == OP_NOT_EMPTY:
                log.info('Authentication will be identified by %s IS NOT EMPTY', self.check_auth_key)

        if self.pm_url is None or self.pm_user is None or self.pm_pw is None:
            log.warning('Profile manager info are missing. New users can not be created')

        controller = 'ckanext.provbzauth.controller:ProvBzAuthController'

        self.ext_login_url = url_for(controller=controller, action='external_login')
        self.ext_logout_url = url_for(controller=controller, action='external_logout')
        self.int_login_url = url_for(controller='user', action='login')
        self.int_logout_url = url_for(controller='user', action='logout')

    def challenge(self, environ, status, app_headers, forget_headers):
        """
        repoze.who.interfaces.IChallenger.challenge.

        "Conditionally initiate a challenge to the user to provide credentials."

        "Examine the values passed in and return a WSGI application which causes a
        challenge to be performed.  Return None to forego performing a challenge."

        :param environ:  the WSGI environment
        :param status:  status written into start_response by the downstream application.
        :param app_headers:  the headers list written into start_response by the downstream application.
        :param forget_headers:
        :return:
        """

        log.info("ProvBzIdentifierPlugin :: challenge")

        request = Request(environ)

        locale_default = environ.get('CKAN_LANG_IS_DEFAULT', True)
        locale = environ.get('CKAN_LANG', None)

        parsed_url = list(urlparse(request.url))
        parsed_url[0] = parsed_url[1] = ''
        requested_url = urlunparse(parsed_url)

        if not locale_default and locale and not requested_url.startswith('/%s/' % locale):
            requested_url = "/%s%s" % (locale, requested_url)

        url = self.int_login_url + "?%s=%s" % ("came_from", requested_url)

        if not locale_default and locale:
            url = "/%s%s" % (locale, url)

        response = Response()
        response.status = 302
        response.location = url

        log.info("ProvBzIdentifierPlugin response: %s (%s)" % (response, response.location))
        return response

    def dumpInfo(self, env):
        for key in sorted(env.iterkeys()):
            log.debug(' ENV %s -> %s', key, env[key])


    def identify(self, environ):
        """
        repoze.who.interfaces.IIdentifier.identify.

        "Extract credentials from the WSGI environment and turn them into an identity."

        This is called for every page load.

        :param environ:  the WSGI environment.
        :return:
        """

        request = Request(environ)

        log.debug("ProvBzIdentifierPlugin :: identify ------------------------------------------------------------")
        # self.dumpInfo(environ)

        # Logout user
        if request.path == self.int_logout_url:
            response = Response()

            for a, v in self.forget(environ, {}):
                response.headers.add(a, v)

            response.status = 302

            # try:
            #     url = url_for(controller='user', action='logged_out')
            # except AttributeError as e:
            #     # sometimes url_for fails
            #     log.warning('Error in url_for: %s', str(e))
            #     url = '/'

            # locale = environ.get('CKAN_LANG', None)
            # default_locale = environ.get('CKAN_LANG_IS_DEFAULT', True)
            # if not default_locale and locale:
            #     url = "/%s%s" % (locale, self.shib_logout_url)

            response.location = self.ext_logout_url
            environ['repoze.who.application'] = response

            log.info("ProvBzAuth user logout successful: %r" % request)
            return {}

        # logout in progress
        if request.path == self.ext_logout_url:
            return {}

        # Login user if there are valid headers
        if self.is_active_session(environ): #  and request.path == self.login_url:
            user = self._get_or_create_user(environ)

            if not user:
                return {}

            # TODO: Fix flash message later, maybe some other place
            #h.flash_success(
            #    _('Profile updated or restored from {idp}.').format(
            #        idp=environ.get('Shib-Identity-Provider',
            #                        'IdP not aquired')))
            response = Response()
            response.status = 302

            url = request.params.get('came_from', None)
            # if not url:
            #     try:
            #         url = toolkit.url_for(controller='package', action='search')
            #     except AttributeError as e:
            #         # sometimes url_for fails
            #         log.warning('Error in url_for: %s', str(e))
            #         url = '/'
            #
            #     locale = environ.get('CKAN_LANG', None)
            #     default_locale = environ.get('CKAN_LANG_IS_DEFAULT', True)
            #     if not default_locale and locale:
            #         url = "/%s%s" % (locale, url)

            if url:
               response.location = url
               environ['repoze.who.application'] = response

            log.info("ProvBzAuth login successful: id:%s name:%s fullname: %s (%s)", user.id, user.name, user.fullname, response.location)

            return {'provbz_auth': user.id}


        # User not logging in or logging out, return empty dict
        return {}

    def _get_or_create_user(self, env):

        eppn = env.get(self.eppn, None)
        # fullname = env.get(self.fullname, None)
        # email = env.get(self.mail, None)
        authtype = env.get(self.auth_type, None)

        if authtype not in ("PROV.BZ", "SIAG.IT"):
            log.info('AuthType %s not allowed', authtype)
            return None

        if not eppn:
            log.info('Environ does not contain user reference, user not loaded.')
            return None

        # compose user id : THIS IS INTEGRATION DEPENDANT!!!
        userkey = eppn + "@" + authtype

        user = model.Session.query(model.User).autoflush(False) \
            .filter_by(openid=userkey).first()

        if user:
            pass
            # Check if user information from shibboleth has changed
            # if user.fullname != fullname or user.email != email:
            #     log.info('User attributes modified, updating.')
            #     user.fullname = fullname
            #     user.email = email

        else:  # user is None:
            log.info('User does not exists, creating new one.')

            user = self._get_user_profile(userkey, env)
            if not user:
                log.warning("Can not retrieve user info")
                return None

            basename = unicode(userkey, errors='ignore').lower().replace(' ',
                                                                         '_')
            username = basename
            suffix = 0
            while not model.User.check_name_available(username):
                suffix += 1
                username = basename + str(suffix)

            user.name = username
            # user = model.User(name=username,
            #                   fullname=fullname,
            #                   email=email,
            #                   openid=userkey)

            model.Session.add(user)
            model.Session.flush()
            log.info('Created new user {usr}'.format(usr=user.fullname))

        model.Session.commit()
        model.Session.remove()
        return user

    def _get_rememberer(self, environ):
        plugins = environ.get('repoze.who.plugins', {})
        return plugins.get('auth_tkt')

    def remember(self, environ, identity):
        '''
        Return a sequence of response headers which suffice to remember the given identity.

        :param environ:
        :param identity:
        :return:
        '''
        rememberer = self._get_rememberer(environ)
        return rememberer and rememberer.remember(environ, identity)

    def forget(self, environ, identity):
        '''
        Return a sequence of response headers which suffice to destroy any credentials used to establish an identity.

        :param environ:
        :param identity:
        :return:
        '''
        rememberer = self._get_rememberer(environ)
        return rememberer and rememberer.forget(environ, identity)

    def _get_user_profile(self, userkey, env):

        uid = env["HTTP_SHIB_IDP_UID"]
        inst = env["HTTP_SHIB_ORIGINAL_AUTHENTICATION_INSTANT"]
        idp = env["HTTP_SHIB_ORIGINAL_IDENTITY_PROVIDER"]

        headers = {
            'Content-type': 'application/json',
            'Shib-Authentication-Instant': inst,
            'Shib-Original-Identity-Provider': idp,
            'Shib-idp-uid': uid}

        r = requests.get(self.pm_url, auth=(self.pm_user, self.pm_pw), headers=headers)  # type: Response

        if r.status_code != requests.codes.ok:
            log.warning('Error received from the profile manager %s', r.status_code)
            return None

        uj = r.json()
        owner = uj.get('owner')
        fullname = owner.get('firstname') + ' ' + owner.get('lastname')
        deleg = uj.get('delegations')[0]
        email = deleg.get('email')

        user = model.User(fullname=fullname,
                          email=email,
                          openid=userkey)

        return user

