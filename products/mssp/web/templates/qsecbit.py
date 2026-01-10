# In your Django views.py
import requests
from django.shortcuts import render

QSECBIT_API = 'http://10.107.0.10:8888'

def dashboard(request):
    # Fetch latest Qsecbit score
    response = requests.get(f'{QSECBIT_API}/api/qsecbit/latest')
    qsecbit_data = response.json()
    
    # Fetch Kali responses
    kali_response = requests.get(f'{QSECBIT_API}/api/kali/responses')
    kali_data = kali_response.json()
    
    context = {
        'qsecbit_score': qsecbit_data['score'],
        'rag_status': qsecbit_data['rag_status'],
        'threat_level': qsecbit_data['components']['attack_probability'],
        'drift': qsecbit_data['components']['drift'],
        'quantum_drift': qsecbit_data['components']['quantum_drift'],
        'kali_responses': kali_data[:5],  # Last 5 responses
    }
    
    return render(request, 'admin/dashboard.html', context)
