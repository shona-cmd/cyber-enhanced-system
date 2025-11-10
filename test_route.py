from naashon_secure_iot.dashboard import patch_dashboard

app = patch_dashboard()

with app.test_client() as client:
    response = client.get('/')
    print(response.status_code)
    print(response.data[:200].decode('utf-8'))
