def test_profile_requires_auth(client):
    resp = client.get("/profile/")
    assert resp.status_code == 302 or resp.status_code == 401
