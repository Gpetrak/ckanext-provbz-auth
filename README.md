SPID authentication plugin for CKAN 2.10. 

Install
=======

You can install ckanext-provbz-auth either with

    pip install -e git+git://github.com/geosolutions-it/ckanext-ckanext-provbz-auth.git#egg=ckanext-provbz-auth
	
or

    git clone https://github.com/geosolutions-it/ckanext-provbz-auth.git
    python setup.py install
        
	
Plugin configuration
====================

ckan.ini configuration
----------------------------

Add ``provbz_auth`` the the ckan.plugins line

     ckan.plugins = [...] provbz_auth

**Important note**: add the ``provbz_auth`` plugin before the ``provbz`` plugin in order the logout funtionality to be applied in both SSO and CKAN users and not only to CKAN users.
     
This plugin was implemented using the following SSO API: https://sso.civis.bz.it/swagger/index.html
Thus, we have to define the following variables in the ckan.ini file:


     ## ckanext-provbz-auth
     ckanext.provbzauth.login_url = https://sso.civis.bz.it/api/Auth/Login
     ckanext.provbzauth.logout_url = https://sso.civis.bz.it/api/Auth/Logout
     validateToken = https://sso.civis.bz.it/api/Auth/Validate
     profile = https://sso.civis.bz.it/api/Auth/Profile
     targetUrl = http://<mysite>/auth_bz
     acceptedAuthTypes = SPID CNS PROV.BZ SIAG.IT GVCC.NET
     serviceUID =
     authLevel = 0
     onlyauth = false
     locale =-it
     forceLogin  = false
     returnUrl = http://<mysite>

Please note that the Login service will accept redirection only from enabled/whitelisted hosts. localhost  is always enabled, so you can test your local CKAN instance without any problem.

External configuration
----------------------

The `ckanext-provbz-auth` extension requires login and logout path handled by the external SP layer.


