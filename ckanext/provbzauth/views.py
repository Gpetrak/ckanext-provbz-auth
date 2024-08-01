# For CKAN 2.10
from ckan.common import CKANConfig as config
from flask import Blueprint
from ckan.plugins.toolkit import render
from ckan.common import request, login_user
import ckan.lib.base as base
from ckan.lib.helpers import redirect_to
from ckan import model
from ckan.plugins.toolkit import render
from ckan.views.user import rotate_token
from ckan.lib.helpers import helper_functions as h
# import re
import requests
from flask import request
import json

import logging
from ckan.views.user import next_page_or_default
from ckan.lib import authenticator

log = logging.getLogger(__name__)

auth_blueprints = Blueprint('auth_blueprints', __name__)

## Define the views
@auth_blueprints.route('/redirect_external_login')
def external_login():

    # Build the query and receive the URL for the myCivis portal
    # API documentation: https://sso.civis.bz.it/swagger/index.html
    resp = requests.get(
                      base.config.get("ckanext.provbzauth.login_url"),
                      params = {"targetUrl": base.config.get("targetUrl"), 
                                "acceptedAuthTypes": base.config.get("acceptedAuthTypes"),
                                "authLevel": base.config.get("authLevel"),
                                "onlyauth": base.config.get("onlyauth"),
                                "forceLogin": base.config.get("forceLogin"),
                                "lang": base.config.get("locale")
                                },
                      allow_redirects=False
                      )
    
    # locale = request.environ.get('CKAN_LANG')
    # login_path = re.sub('{{LANG}}', str(locale), login_path)

    log.info("REDIRECTING TO %r", redirect_to(resp.url))

    # TODO: we whoud check if the login_path is relative or absolute.
    #    When relative, we should use base.h.redirect_to(login_path),
    #    but the apache shibboleth filter should be aware of the
    #    language path part (e.g. /it )

    return redirect_to(resp.url)

    # if base.c.userobj is not None:
    #     log.info("Repoze.who Shibboleth controller received userobj %r " % base.c.userobj)
    #     return base.h.redirect_to(controller='user',
    #                               action='read',
    #                               id=base.c.userobj.name)
    # else:
    #     log.error("No userobj received in Repoze.who Shibboleth controller %r " % base.c)
    #     base.h.flash_error(_("No user info received for login"))
    #     return base.h.redirect_to('/')

# This view retrieves the token and validates it.
# The endpoint "http://localhost:5000/auth_bz" is the targetUrl parameter of the api/Auth/login from
# the API documentation: https://sso.civis.bz.it/swagger/index.html
@auth_blueprints.route('/auth_bz')
def do_authenticate():
    
    token = request.args['token']
    # endpoint: /api/Auth/Validate/{token}
    resp_val = requests.get(
                      base.config.get("validateToken") + '/{}'.format(token),
                      )

    # Check authentication
    if resp_val.status_code==200:
        resp_prof = requests.get(
                           base.config.get("profile") + '/{}'.format(token)
                           )
        # convert the resp_prof response from string to json
        profile_info = json.loads(resp_prof.text)

        # log.info("profile %r", resp_prof.text)
        # Get the User profile ID
        userid = profile_info["owner"]["fiscalCode"]
        username = profile_info["username"]
        firstname = profile_info["owner"]["firstname"]
        lastname = profile_info["owner"]["lastname"]

        log.info("userid %r", userid)
        name_id = username + "@" + str(userid)

        user = model.Session.query(model.user.User).autoflush(False) \
            .filter_by(name=name_id).first()

        log.info("user %r", user)
        # Test if the user with the same ID exists on CKAN
        if user is None: #or not user.is_active():
            log.info("do_authenticate: user not found: %s", name_id)
            log.info("Provbz auth service will create an internal user with the ID: %s", userid)
            # Create the new user
            # example_user = model.user.User(name = "id@gpetr", fullname = "George Petrakis")
            new_user = model.user.User(name = name_id, fullname = firstname + ' ' + lastname)
            # Add the user to the database table
            model.Session.add(new_user)
            # Store it in the database
            model.Session.commit()

            login_user(new_user)
            rotate_token()

            return h.redirect_to(u'http://localhost:5000')
            
        else:

            log.info("The user {} exists".format(userid))
            login_user(user)
            rotate_token()

            return h.redirect_to(u'http://localhost:5000')

        return redirect_to("http://localhost:5000/user/login")
    
    


@auth_blueprints.route('/redirect_external_logout')
def external_logout():
    
    # Retrieve the logout redirected path from the configuration file
    logout_resp = requests.get(
                      base.config.get("ckanext.provbzauth.logout_url"),
                      params = {"returnUrl": base.config.get("returnUrl")},
                      allow_redirects=False
                      )
    
    log.info("logout URL %r", logout_resp.url)

    return redirect_to(logout_resp.url)

def get_blueprints():
    return [auth_blueprints]