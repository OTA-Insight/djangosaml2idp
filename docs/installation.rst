Django Saml2 IDP
================

Installation
------------

PySAML2 uses `XML Security Library <http://www.aleksey.com/xmlsec/>`_ binary to sign SAML assertions, so you need to install
it either through your operating system package or by compiling the source code. It doesn't matter where the final executable is installed because
you will need to set the full path to it in the configuration stage. XmlSec is available (at least) for Debian, OSX and Alpine Linux.

Now you can install the djangosaml2idp package using pip. This will also install PySAML2 and its dependencies automatically::

    pip install djangosaml2idp
