# This method will be used by the mock to replace requests.get
def mocked_requests_get(*args, **kwargs):
    class MockResponse:
        def __init__(self, text, status_code):
            self.text = text
            self.status_code = status_code

    if args[0] == 'http://not_found':
        return MockResponse('not found', 404)

    return MockResponse('ok', 200)
