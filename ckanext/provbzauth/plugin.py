'''
SPID authentication plugin for CKAN
'''
import ckan.plugins as plugins
import ckan.plugins.toolkit as toolkit

import ckanext.provbzauth.views as views
import logging

# from ckan.lib.plugins import DefaultTranslation  # CKAN 2.5 only


log = logging.getLogger(__name__)


class ProvBzAuthPlugin(plugins.SingletonPlugin
     # , DefaultTranslation  # CKAN 2.5 only
    ):
    '''
    ProvBz auth plugin for CKAN
    '''

    # IBlueprint
    plugins.implements(plugins.IBlueprint)
    # plugins.implements(plugins.IRoutes, inherit=True)
    plugins.implements(plugins.IConfigurer)
    # plugins.implements(plugins.ITranslation)  # CKAN 2.5 only

    def update_config(self, config):
        """
        Override both IConfigurer and ITranslation
        """
        toolkit.add_template_directory(config, 'templates')
        toolkit.add_public_directory(config, 'public')

    
    # Implementation of IBlueprints
    # ------------------------------------------------------------
    def get_blueprint(self):
        return views.get_blueprints()
    
    '''
    def before_map(self, map):
        """
        Override IRoutes.before_map()
        """
        controller = 'ckanext.provbzauth.controller:ProvBzAuthController'
        map.connect('provbzauth',
                    "/redirect_external_login",
                    controller=controller,
                    action='external_login')

        map.connect('provbzauth',
                    "/redirect_external_logout",
                    controller=controller,
                    action='external_logout')

        return map
    '''
