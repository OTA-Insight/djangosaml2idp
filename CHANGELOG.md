# Changelog

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