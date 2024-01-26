#!/usr/bin/env python3
"""
End-to-end integration tests for the API.
"""

import requests


def register_user(email: str, password: str) -> None:
    """
    Test user registration endpoint
    :param email: The email of the user
    :param password: The password of the user
    :return: None if the user was created, otherwise an error
    """
    response = requests.post('http://127.0.0.1:5000/users', data={
        'email': email,
        'password': password
    })

    if response.status_code == 200:
        assert (response.json() == {"email": email, "message": "user created"})
    else:
        assert (response.status_code == 400)
        assert (response.json() == {"message": "email already registered"})


def log_in_wrong_password(email: str, password: str) -> None:
    """
    Test user login endpoint
    :param email: The email of the user
    :param password: The password of the user
    :return: Assert that the response is 401
    """
    response = requests.post('http://127.0.0.1:5000/sessions', data={
        'email': email,
        'password': password
    })

    assert (response.status_code == 401)


def log_in(email: str, password: str) -> str:
    """
    Test user login endpoint
    :param email: The email of the user
    :param password: The password of the user
    :return: Session ID if the user was logged in, otherwise an error
    """
    response = requests.post('http://127.0.0.1:5000/sessions', data={
        'email': email,
        'password': password
    })

    if response.status_code == 200:
        assert (response.json() == {"email": email, "message": "logged in"})
        return response.cookies.get('session_id')
    else:
        assert (response.status_code == 401)


def profile_unlogged() -> None:
    """
    Test profile endpoint
    :return: Assert that the response is 403
    """
    response = requests.get('http://127.0.0.1:5000/profile')
    assert (response.status_code == 403)


def profile_logged(session_id: str) -> None:
    """
    Test profile endpoint
    :param session_id: The session ID of the user
    :return: Assert that the response is 200
    """
    cookies = {'session_id': session_id}
    response = requests.get('http://127.0.0.1:5000/profile', cookies=cookies)
    assert (response.status_code == 200)


def log_out(session_id: str) -> None:
    """
    Test for log out with the given session_id.
    Args:
        session_id: The session_id of the user.
    Returns:
        None
    """
    cookies = {'session_id': session_id}
    r = requests.delete('http://127.0.0.1:5000/sessions',
                        cookies=cookies)
    if r.status_code == 302:
        assert (r.url == 'http://127.0.0.1:5000/')
    else:
        assert (r.status_code == 200)


def reset_password_token(email: str) -> str:
    """
    Test for reset password token with the given email.
    Args:
        email: The email of the user.
    Returns:
        The reset_token of the user.
    """
    r = requests.post('http://127.0.0.1:5000/reset_password',
                      data={'email': email})
    if r.status_code == 200:
        token = r.json().get('reset_token')
        assert (r.json() == {"email": email, "reset_token": token})
    else:
        assert (r.status_code == 403)


def update_password(email: str, reset_token: str,
                    new_password: str) -> None:
    """
    Test for update password with the given email,
    reset_token and new_password.
    Args:
        email: The email of the user.
        reset_token: The reset_token of the user.
        new_password: The new password of the user.
    Returns:
        None
    """
    data = {'email': email, 'reset_token': reset_token,
            'new_password': new_password}
    r = requests.put('http://127.0.0.1:5000/reset_password',
                     data=data)
    if r.status_code == 200:
        assert (r.json() == {"email": email, "message": "Password updated"})
    else:
        assert (r.status_code == 403)


EMAIL = "guillaume@holberton.io"
PASSWD = "b4l0u"
NEW_PASSWD = "t4rt1fl3tt3"

if __name__ == "__main__":
    register_user(EMAIL, PASSWD)
    log_in_wrong_password(EMAIL, NEW_PASSWD)
    profile_unlogged()
    session_id = log_in(EMAIL, PASSWD)
    profile_logged(session_id)
    log_out(session_id)
    reset_token = reset_password_token(EMAIL)
    update_password(EMAIL, reset_token, NEW_PASSWD)
    log_in(EMAIL, NEW_PASSWD)
