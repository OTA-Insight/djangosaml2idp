Example SP/IdP implementation
=============================

This is a barebone example implementation of a functional setup with a Service Provider and Identity Provider.
The SP is implemented using `djangosaml2 <https://github.com/knaperek/djangosaml2/>`_, the IdP using djangosaml2idp.
Both are default django projects with only the bare minimum of added code for a functional demo.
This is meant to easily highlight only the parts necessary to implement the SP/IdP functionality in your own without other code clutter serving as distraction.

A `docker-compose <https://docs.docker.com/compose/>`_ file is included, providing a minimum-entry-barrier setup to get up and running, without complicated & error-prone setup requirements.
The example will run equally on Mac/Windows/Linux using docker.

How to run
----------

Go to this folder in a terminal and start the containers::

    docker-compose up -d

Give it a minute the first time to download and build the required images. They'll be cached for successive runs.
You now have a SP running at http://localhost:8000/ and a IdP at http://localhost:9000/ (you can check your containers using :code:`docker-compose ps`), configured to talk with each other.
In order to do an actual login, you will need to create a user account on the IdP. Run this in a terminal with your containers running to create a new user:

    docker exec -it djangosaml2idp_idp python manage.py createsuperuser

You can follow the logs via.

    docker-compose logs -f idp
    docker-compose logs -f sp

If you don't want to use docker, simply do in a terminal from the idp directory

    pip install -r requirements.txt

    python manage.py migrate

    python manage.py runserver 0.0.0.0:9000 (8000 for the SP) in a terminal

How to use
----------


There are two flows illustrated with this demo:


1. SP-initiated login
    - Go to the `SP <http://localhost:8000/>`_ in your browser and verify you are not logged in.
    - Click on the login link. You'll get redirected to a login form on the IdP instance.
    - Log in with your credentials from the user you just created. You get redirected back to the SP instance.
    - You are now logged in on the SP. The page shows the user information stemming from the IdP.


2. IDP-initiated login
    - Go to the `SP <http://localhost:8000/>`_ in your browser and verify you are not logged in.
    - Go to the `IDP <http://localhost:9000/>`_ in your browser. You are not logged in.
    - Click on the login link. You'll get redirected to a login form on the IdP instance.
    - Log in with your credentials from the user you just created. You get back to the IDP landing page, but now you are logged in.
    - Click the link on the bottom saying "Perform IDP-initiated login ...".
    - You get redirected to the SP and are now logged in.


At no point in the two steps below did you login on the SP; all logins happen on the IDP. The authentication information is then passed to the SP.
And that is essentially what SSO with SAML2 does :)


Cleanup
-------

To stop the containers::

    docker-compose stop


Certificate generation
----------------------

The provided self-signed certificates included in this example are valid until 2028. Should you need to regenerate them, you can use the `generate.sh` script to generate new ones.
For e.g. the IdP certificate:

1. Ensure the subj has the correct hostname in the openssl command:  `/CN=idp.localhost.com`
2. Execute the script: `./generate.sh`. This will create a private.key & public.cert pair
3. Copy the newly create files to the idp/certificates folder
4. Copy the public.cert content without the first and last line into the sp/saml2_config/idp_metadata.xml tags `ns2:X509Certificate` (there are 2 of them)

For the SP certificates, the process is the same but the hostname is `sp.localhost.com` and in step 3 & 4 switch idp with sp folder.
