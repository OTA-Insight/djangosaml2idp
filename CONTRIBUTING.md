# Contributing to the djangosaml2idp package

First of all, thank you for contributing to the project! The more, the merrier.

I welcome all contributions; issues/bug reports, adding tests, adding or requesting functionality, improving documentation, suggesting implementation improvements ...

## About the project

This package started off on a need-to-have basis for use in the company I work for. I did not spend time to build an all-encompassing feature set; so what we did not use and need was not implemented. Several features since then have been added by contributors with their own needs in mind. Therefore, if something is missing that you need, feel free to ask about it and I'm happy to take a look.

While I created this package due to a need in the company for something like this, I maintain it privately. I am not paid for it nor work on it during 'company time', it is a private side project. My response time will therefore be dependent on my available time and is a best-effort matter. Please keep this in mind and my apologies in advance if a response runs a bit late. We all have lives to lead :)

## Practicalities

Some notes for when you want to start adding code to the project.

### Tests

- Unfortunately there are not a lot of formal tests (there's an idea for a contribution ;)) Please make sure that the ones who are present, succeed by running the test suite (it uses `pytest`, instructions are in the [README.rst](README.rst))

### Codestyle

- Formatting: I mostly like to follow the PEP8 standard, with some customized rules applied.
- For code quality and consistency checks, I recommend the [PyLama](https://github.com/klen/pylama) tool. You run it by executing
    ```bash
    pylama --options pytest.ini
    ```
    in the root of the project. It only outputs violations, so if you don't get any output, you did great. Please ensure pylama succeeds when creating a PR.
- When you create a PR for functionality or bugfix, don't mix in unrelated formatting changes along with it.


The `pytest.ini` file contains sections for both PEP8 and pylama settings, which should be used for this project.