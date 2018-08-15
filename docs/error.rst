Customizing error handling
--------------------------

djangosaml2idp renders a very basic error page if it encounters an error, indicating an error occured, which error, and possibly an extra message.
The HTTP status code is also set if possible depending on which error occured.
You can customize this by using the `SAML_IDP_ERROR_VIEW_CLASS` setting. Set this to a dotted import path to your custom (class based) view in order to use that one.
If you subclass the provided `djangosaml2idp.error_views.SamlIDPErrorView`, you have the following variables available for use in the template:

exception_type
  the class of the exception that occurred

exception_msg
  the message from the exception (by doing `str(exception)`)

extra_message
  if no specific exception given, a message indicating something went wrong, or an additional message next to the `exception_msg`

The simplest override is to subclass the `SamlIDPErrorView` and only using your own error template.
You can use any Class-Based-View for this; it's not necessary to subclass the builtin error view.
The example project contains a ready to use example of this; uncomment the `SAML_IDP_ERROR_VIEW_CLASS` setting and it will use a custom view with custom template.
