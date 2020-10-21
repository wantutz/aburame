ShieldX Common Test Infrastructure
----------------------------------

Usage::
    $ python3
    >>>
    >>> from sxswagger.rest_session import RestSession as RS
    >>>
    >>> umip = "172.16.27.73"
    >>> username = "user1"
    >>> password = "password!23"
    >>>
    >>> rs = RS(ip=umip, username=username, password=password)
    >>> rs.login()

