from naashon_secure_iot.dashboard import app

with app.test_client() as client:
    response = client.get('/apa_guide')
    print(response.status_code)
    print(response.data[:200].decode('utf-8'))
