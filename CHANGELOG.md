# Changelog

## [0.6.3] - 2020-02-10

Bugfix release, thanks to contributions from [pix666](https://github.com/pix666) in [#61](https://github.com/OTA-Insight/djangosaml2idp/pull/61/files)

## [0.6.2] - 2020-02-03

Bugfix release, thanks to contributions from [@mjholtkamp](https://github.com/mjholtkamp) in [#54](https://github.com/OTA-Insight/djangosaml2idp/pull/54),
[#55](https://github.com/OTA-Insight/djangosaml2idp/pull/55), and
[#56](https://github.com/OTA-Insight/djangosaml2idp/pull/56)

## [0.6.1] - 2019-12-13

Many thanks for contributions to [@askvortsov1](https://github.com/askvortsov1) and [@peppelinux](https://github.com/peppelinux) for the contributions in this release

### Added
- More NameID formats supported, and a check on support for a format by the IDP was added. [#32](https://github.com/OTA-Insight/djangosaml2idp/issues/32), [#38](https://github.com/OTA-Insight/djangosaml2idp/issues/38), [#46](https://github.com/OTA-Insight/djangosaml2idp/issues/45)
- The field on user to be used for the NameID can now be configured per SP via the `nameid_field` in the `SAML_IDP_SPCONFIG`.
- The setting for signed responses and assertions can be configured per SP in the `SAML_IDP_SPCONFIG`. The default algorithm if not specified has been upgraded from SHA1 to SHA256. [#35](https://github.com/OTA-Insight/djangosaml2idp/issues/35)
- SLO (single_logout_service) support for both POST and REDIRECT binding. The path of the new view is `slo/<str:binding>/`. [#23](https://github.com/OTA-Insight/djangosaml2idp/issues/23)
- The `attribute_mapping` per SP in the `SAML_IDP_SPCONFIG` for constructing the identity dict now accepts a callable method on an object next to a normal attribute.
- Assertions can now be encrypted. This can be configured per SP using the `encrypt_saml_responses` in the `SAML_IDP_SPCONFIG`, and set globally using the `SAML_ENCRYPT_AUTHN_RESPONSE` setting. [#36](https://github.com/OTA-Insight/djangosaml2idp/issues/36)

### Changed
- **BREAKING CHANGE**: the `create_identity(...)` method on the Processor class has had it's signature change. It now does not accept extra kwargs anymore, only the user and the attribute_mapping. This might or might not be relevant to you; it is if you have subclassed a processor and have customized the `create_identity` method there.
- Improved logging with pretty representation of requests/responses.

## [0.5.0] - 2019-01-12

Many thanks for contributions to [@lgarvey](https://github.com/lgarvey)

### Added
- The user identifier attribute is now customizable via the `SAML_IDP_DJANGO_USERNAME_FIELD` settings. [PR#20](https://github.com/OTA-Insight/djangosaml2idp/pull/20)
- Supports the HTTP REDIRECT binding. [PR#20](https://github.com/OTA-Insight/djangosaml2idp/pull/20)
- Bugfix in the NameID generation where destination instead of entity ID was used. [#18](https://github.com/OTA-Insight/djangosaml2idp/issues/18)

### Changed
- **BREAKING CHANGE**: the `has_access(user)` method on the Processor class has been changed to `has_access(request)`. This to allow a broader scope of access control checks to perform. If you have subclassed the `BaseProcessor` class and have overriden this method with a custom implementation, you will need to change this.

## [0.4.1] - 2018-08-09

Many thanks for contributions to [@jlunger-arcweb](https://github.com/jlunger-arcweb)

### Added
- IDP-initiated login
- Example project extended with IDP-initiated login and improved docs on it

## [0.4.0] - 2018-08-08

Many thanks for contributions to [@peppelinux](https://github.com/peppelinux), [@saundersmatt](https://github.com/saundersmatt), [@JosephKiranBabu](https://github.com/JosephKiranBabu)

### Added
- Python 3 support
- Django 2.x supported. Tested with 2.0 and 2.1
- Added some docstring on certain methods
- Added decorators to the views to restrict allowed HTTP methods, and disable browser caching of the views.

### Changed
- Multi Factor Authentication: view is now a Class-Based View for easier subclassing. Functionality remains the same, so users who have implemented their own view with this name will not break.
- Updated certificates included in the example project
- Reworked login process view to a CBV.
- Small updates to example project to show where you are in the browser.

### Removed
- Python 2 support
- Django < 2.x support

## [0.3.0] - 2017

Many thanks for contributions to [@goetzk](https://github.com/goetzk)

### Added
- Multi factor authentication