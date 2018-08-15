Multi Factor Authentication support
===================================

There are three main components to adding multiple factor support.


1. Subclass djangosaml2idp.processors.BaseProcessor as outlined above. You will need to override the `enable_multifactor()` method to check whether or not multifactor should be enabled for a user. (If it should allways be enabled for all users simply hard code to True). By default it unconditionally returns False and no multifactor is enforced.

2. Sublass the `djangosaml2idp.views.ProcessMultiFactorView` view to make the appropriate calls for your environment. Implement your custom verification logic in the `multifactor_is_valid` method: this could call a helper script, an internal SMS triggering service, a data source only the IdP can access or an external second factor provider (e.g. Symantec VIP). By default this view will log that it was called then redirect.

3. Update your urls.py and add an override for name='saml_multi_factor' - ensure it comes before importing the djangosaml2idp urls file so your custom view is used instead of the built-in one.
