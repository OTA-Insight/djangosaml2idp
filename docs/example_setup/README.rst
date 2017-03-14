Example SP/IdP implementation
=============================

This is a barebone example implementation of a setup with a Service Provider and Identity Provider.
The SP is implemented using djangosaml2, the IdP using djangosaml2idp.
Both are default django projects with only the bare minimum of added code for a functional demo or start.
This to keep it clear and obvious how to implement the SP/IdP functionality without other clutter serving as distraction.

A docker-compose_ file is included, providing a minimum-entry-barrier setup to get up and running, without complicated & error-prone setup requirements.
The example will run equally on Mac/Windows/Linux using docker.

.. _docker-compose: https://docs.docker.com/compose/

How to run
----------

Go to this folder in a terminal and start the containers::

    docker-compose up -d

Give it a minute the first time to download and build the required images. They'll be cached for the successive runs.
You now have a SP running at http://localhost:8000/ and a IdP at http://localhost:9000/ (you can check with :code:`docker-compose ps`), configured to talk with each other.
In order to do some login, you will need to create a user account on the IdP::

    docker exec -it djangosaml2idp_idp python manage.py createsuperuser

Now go to the SP in your browser. The page shows you're not logged in; click on the link to login. You'll get redirected to the IdP which
shows a basic login form. Enter the credentials from the user you just created. You will then get redirected back to the SP, showing you are logged in with the user information.
And that is essentially what SAML2 does :)

Cleanup
-------

To stop the containers::

    docker-compose stop