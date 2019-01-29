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

who.ini configuration
---------------------

Add the ``plugin:provbz-auth`` section, customizing the env var names:

    [plugin:provbz-auth]
    use = ckanext.provbzauth.repoze.ident:make_identification_plugin

    session = YOUR_HEADER_FOR_Shib-Session-ID
    eppn = YOUR_HEADER_FOR_eppn
    mail = YOUR_HEADER_FOR_mail
    fullname = YOUR_HEADER_FOR_cn

    check_auth_key=AUTH_TYPE
    check_auth_value=

``check_auth_key`` and ``check_auth_value`` are needed to find out if we are receiving info from the Shibboleth module. Customize both right-side values if needed. For instance, older Shibboleth implementations may need this configuration:

    check_auth_key=HTTP_SHIB_AUTHENTICATION_METHOD 
    check_auth_value=urn:oasis:names:tc:SAML:1.0:am:unspecified
    

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

production.ini configuration
----------------------------

Add ``provbz_auth`` the the ckan.plugins line

     ckan.plugins = [...] provbz_auth
     
Configure external login and logout URLs:

     ckanext.provbzauth.login_url = https://test-data.civis.bz.it/Shibboleth.sso/Login?target=https%3A%2F%2Ftest-data.civis.bz.it&authnContextClassRef=SPID+CNS+PROV.BZ+SIAG.IT+GVCC.NET+lang%3a{{LANG}}
     ckanext.provbzauth.logout_url = https://test-data.civis.bz.it/Shibboleth.sso/Logout

External configuration
----------------------

The `ckanext-provbz-auth` extension requires login and logout path handled by the external SP layer.


