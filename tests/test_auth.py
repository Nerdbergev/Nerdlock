def test_login_page(client):
    """Test that login page loads"""
    resp = client.get("/login")
    assert resp.status_code == 200
    assert b"Login" in resp.data


def test_login_nonexistent_user(client):
    """Test login with nonexistent user"""
    resp = client.post("/login", data={"email": "nonexistent@test.com", "password": "pass"})
    assert resp.status_code == 200


def test_webauthn_manage_requires_auth(client):
    """Test that webauthn management requires authentication"""
    resp = client.get("/auth/webauthn/manage")
    assert resp.status_code == 302 or resp.status_code == 401
