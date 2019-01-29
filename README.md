SPID authentication plugin for CKAN 2.4. 

Install
=======

You can install ckanext-provbz-auth either with

    pip install -e git+git://github.com/geosolutions-it/ckanext-ckanext-provbz-auth.git#egg=ckanext-provbz-auth
	
or

    git clone https://github.com/geosolutions-it/ckanext-provbz-auth.git
    python setup.py install
        
	
Plugin configuration
====================

production.ini configuration
----------------------------

Add ``provbz_auth`` the the ckan.plugins line

     ckan.plugins = [...] provbz_auth
     
Configure external login and logout URLs:

     ckanext.provbzauth.login_url = https://test-data.civis.bz.it/Shibboleth.sso/Login?target=https%3A%2F%2Ftest-data.civis.bz.it&authnContextClassRef=SPID+CNS+PROV.BZ+SIAG.IT+GVCC.NET+lang%3a{{LANG}}
     ckanext.provbzauth.logout_url = https://test-data.civis.bz.it/Shibboleth.sso/Logout


who.ini configuration
---------------------

Add the ``plugin:provbz_auth`` section, customizing the env var names:

    [plugin:provbz_auth]
    use = ckanext.provbzauth.repoze.ident:make_identification_plugin

    check_auth_key = HTTP_SHIB_ORIGINAL_AUTHENTICATION_INSTANT
    check_auth_op = not_empty   
    # check_auth_value=

    eppn = HTTP_SHIB_IDP_UID
    authtype = HTTP_SHIB_AUTHTYPE

    pm_url = https://test-profilemanager....
    pm_user = ...
    pm_pw = ...
    

Add ``provbz_auth`` to the list of the identifier plugins:

    [identifiers]
    plugins =
        provbz_auth
        friendlyform;browser
        auth_tkt

Add ``ckanext.provbzauth.repoze.auth:ProvbzAuthenticator`` to the list of the authenticator plugins:

    [authenticators]
    plugins =
        auth_tkt
        ckan.lib.authenticator:UsernamePasswordAuthenticator
        ckanext.provbzauth.repoze.auth:ProvbzAuthenticator

Add ``provbz_auth`` to the list of the challengers plugins:

    [challengers]
    plugins =
        provbz_auth
    #    friendlyform;browser
    #   basicauth


External configuration
----------------------

The `ckanext-provbz-auth` extension requires login and logout path handled by the external SP layer.


