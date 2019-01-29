'''
Repoze.who ProvBzAuthController controller
'''

import logging
import re

from pylons.i18n import _

import ckan.controllers.user as user
import ckan.lib.base as base
from ckan.common import request

log = logging.getLogger(__name__)


class ProvBzAuthController(user.UserController):

    def external_login(self):

        login_path = base.config.get("ckanext.provbzauth.login_url", "/shibboleth/login")

        locale = request.environ.get('CKAN_LANG')
        login_path = re.sub('{{LANG}}', str(locale), login_path)

        return base.h.redirect_to(login_path)

        # if base.c.userobj is not None:
        #     log.info("Repoze.who Shibboleth controller received userobj %r " % base.c.userobj)
        #     return base.h.redirect_to(controller='user',
        #                               action='read',
        #                               id=base.c.userobj.name)
        # else:
        #     log.error("No userobj received in Repoze.who Shibboleth controller %r " % base.c)
        #     base.h.flash_error(_("No user info received for login"))
        #     return base.h.redirect_to('/')

    def external_logout(self):

        logout_path = base.config.get("ckanext.provbzauth.logout_url", "/shibboleth/logout")

        return base.h.redirect_to(logout_path)
