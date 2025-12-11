def test_doors_index_requires_auth(client):
    """Test that unauthenticated access to doors redirects"""
    resp = client.get("/doors/")
    assert resp.status_code == 302 or resp.status_code == 401


def test_door_logs_requires_auth(client):
    """Test that door logs require authentication"""
    resp = client.get("/doors/logs")
    assert resp.status_code == 302 or resp.status_code == 401
