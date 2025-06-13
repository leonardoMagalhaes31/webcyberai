from flask import Flask, render_template, request
from utils import analysis  # importa seu módulo analysis.py

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('index.html', aba_ativa='ip')

@app.route('/analisar', methods=['POST'])
def analisar():
    target = request.form.get('target')
    is_ip = analysis.is_ip(target)

    dados_abuse = analysis.consultar_abuseipdb(target) if is_ip else None
    dados_vt = analysis.consultar_virustotal(target, 'ip_addresses' if is_ip else 'domains')
    dados_shodan = analysis.consultar_shodan(target) if is_ip else None

    resultado = ""
    if dados_abuse:
        resultado += f"AbuseIPDB Abuse Score: {dados_abuse['abuseConfidenceScore']}, Total Reports: {dados_abuse['totalReports']}<br>"
    if dados_vt:
        stats = dados_vt['last_analysis_stats']
        resultado += f"VirusTotal Reputation: {dados_vt['reputation']}<br>"
        resultado += f"Malicious: {stats.get('malicious', 0)}, Suspicious: {stats.get('suspicious', 0)}, Undetected: {stats.get('undetected', 0)}<br>"
    if dados_shodan:
        resultado += f"Shodan Org: {dados_shodan['org']}, OS: {dados_shodan['os']}, Ports: {dados_shodan['ports']}<br>"

    return render_template('index.html', resultado_ip=resultado, aba_ativa='ip')

@app.route('/analisar_hash', methods=['POST'])
def analisar_hash():
    hash_val = request.form.get('hash')
    dados_vt = analysis.consultar_virustotal(hash_val, 'files')

    resultado = ""
    if dados_vt:
        stats = dados_vt.get('last_analysis_stats', {})
        resultado += f"Reputação: {dados_vt.get('reputation', 0)}<br>"
        resultado += f"Malicious: {stats.get('malicious', 0)}, Suspicious: {stats.get('suspicious', 0)}, Undetected: {stats.get('undetected', 0)}<br>"

    return render_template('index.html', resultado_hash=resultado, aba_ativa='hash')

@app.route('/upload', methods=['POST'])
def upload():
    file = request.files.get('file')
    if not file:
        return render_template('index.html', resultado_file="Nenhum arquivo enviado.", aba_ativa='file')

    scan_id = analysis.enviar_arquivo_virustotal(file)
    if not scan_id:
        return render_template('index.html', resultado_file="Erro ao enviar arquivo para análise.", aba_ativa='file')

    status = analysis.consultar_status_arquivo(scan_id)
    resultado = f"Análise do arquivo enviada. Status: {status}"

    return render_template('index.html', resultado_file=resultado, aba_ativa='file')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
