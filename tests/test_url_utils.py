from app.url_utils import checkDomain

def test_check_domain():
    assert checkDomain("example.com") == 0

    assert checkDomain("sub.example.com") == 0

    assert checkDomain("example") == -1

    assert checkDomain("example..com") == -1

    assert checkDomain("example-.com") == -1

    assert checkDomain("exam2@ple.com") == -1

    assert checkDomain("-example.com") == -1

    assert checkDomain("ex_ample.com") == -1
