def test_admin_index_requires_admin(client):
    """Test that unauthenticated access redirects"""
    resp = client.get("/admin/")
    assert resp.status_code == 302 or resp.status_code == 403
