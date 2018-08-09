# Changelog

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