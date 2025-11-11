<<<<<<< HEAD
from naashon_secure_iot.dashboard import patch_dashboard

app = patch_dashboard()

with app.test_client() as client:
    response = client.get('/')
=======
from naashon_secure_iot.dashboard import app

with app.test_client() as client:
    response = client.get('/apa_guide')
>>>>>>> 987dbfdcb37af8b3e0f45be86e60819802a6ae51
    print(response.status_code)
    print(response.data[:200].decode('utf-8'))
