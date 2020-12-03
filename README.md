# Hello WebAuthn!

This is a demonstration of integrating webauthn API into a Django website. 

I'm utilizing fido2 (yubico) for the technical implementation of FIDO2 (see their FIDO2.py) and modifying the user authentiation and administration mechanisms
 of django framework to suit a completely passwordless authentication platform.


## Custom Models

Authentication workflow had to shift from the typical Administrator makes user/password, gives password, new user logs in, maybe(?) changes password...

So I've introduced a Token class that uses the secure password reset token generator with limited-time-window and single-use validity. 
 Additionally, there is an Authenticator class that stores (effectively) b64encoded key details. Here is the relational mapping of those objects relative to
 auth.User.

![Django Model Diagram](./mywebauthn/static/img/models.png?raw=true)


## Webauthn Registration Workflow

Registration of webauthn/fido2 authenticators can be performed asynchronously between browser and server so I've opted for this process here.

1. Administrator creates a new user and corresponding registration token (same tokens generated for password reset emails in django).
2. New user visit login page, enters token, clicks register
3. JS post fetch() against 'fido2_register_begin' (/user/api/register/begin) endpoint with token as form payload
4. the server will invalidate the token and store the associated username in the session bucket.
5. response is a cbor encoded stream, once decoded it provides options for navigator.credential.create() to generate a new keypair.
6. key data is extracted and JS post-fetch()ed against 'fido2_register_complete' (/user/api/register/complete)
7. the server then completes the authenticator registration, logs the user for the session, and the user is redirected to the homepage.

![Django Register View](./mywebauthn/static/img/register_view.png?raw=true)


## Webauthn Login Workflow

Login is also performed asynchronously.

1. User returns to website, visits login page, enters username, clicks Login.
2. A JS post fetch() against 'fido2_login_begin' (/user/api/login/begin) endpoint with username as form payload fires.
3. The server will save the username in session bucket, then retrieve all credential-ids and challenges associated with that user and return as a CBOR payload.
4. The results are decoded and passed to navigator.credentials.get().
5. The challenge's response will be CBOR encoded and JS post-fetch()ed to 'fido2_login_complete' for verification.
6. The server then verifies the response against the stored public key, the user is logged in, and redirected to the homepage.

![Django Login View](./mywebauthn/static/img/login_view.png?raw=true)


## Javascript in Template

I opted to build some of the javascript literals from Django's templating language, specifically the {% url .. %} templatetag for named endpoints. I was able
 to generalize the registration/login workflows so they can be neatly wrapped based on which path is being executed (which button clicked).

![Django Login/Registration Template](./mywebauthn/static/img/login_template.png?raw=true)
![Django Login/Registration Javascript](./mywebauthn/static/img/login_javascript.png?raw=true)
