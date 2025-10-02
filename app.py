# In app.py
from flask import Flask, request, render_template
from blockchain import get_connection_status, contract # Import contract object
from firewall import analyze_request

app = Flask(__name__)

@app.route('/')
def index():
    analysis_result = analyze_request(request)
    status = get_connection_status()

    # CORRECTLY fetch all logs from the smart contract
    log_count = contract.functions.getLogsCount().call() # Use the new function
    all_logs = []
    for i in range(log_count):
        log = contract.functions.allLogs(i).call()
        all_logs.append(log)
    
    all_logs.reverse()

    return render_template('index.html', status=status, logs=all_logs)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)