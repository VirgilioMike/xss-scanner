import requests
from bs4 import BeautifulSoup as bs
from collections import Counter
import json
import datetime
import os

# Função para pegar todos os formulários de uma URL
def get_all_forms(url):
    """Captura todos os formulários de uma página web"""
    try:
        response = requests.get(url)
        response.raise_for_status()  # Levanta exceção para códigos HTTP de erro
        soup = bs(response.content, "html.parser")
        return soup.find_all("form")
    except requests.exceptions.RequestException as e:
        print(f"[!] Erro ao acessar a URL: {e}")
        return None  # Retorna None se houver algum problema ao acessar a URL

# Função para extrair os detalhes do formulário
def get_form_details(form):
    """Extrai os detalhes do formulário"""
    details = {}
    action = form.attrs.get("action", "")
    method = form.attrs.get("method", "get").lower()
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")  # Se não houver tipo, será considerado 'text'
        input_name = input_tag.attrs.get("name")
        inputs.append({"type": input_type, "name": input_name})
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details

# Dicionário para mapear payloads a CVEs
payload_to_cve = {
    "<script>alert('XSS')</script>": "CVE-2020-11022",
    "\"'><script>alert('XSS')</script>": "CVE-2019-11358",
    "<img src=x onerror=alert('XSS')>": "CVE-2020-7598"
}

# Dicionário com explicações técnicas dos payloads
payload_descriptions = {
    "<script>alert('XSS')</script>": "Tenta executar um script de alerta simples usando a tag <script>.",
    "\"'><script>alert('XSS')</script>": "Quebra a estrutura HTML e injeta um script malicioso.",
    "<img src=x onerror=alert('XSS')>": "Injeta código malicioso usando evento de erro em imagem."
}

# Relacionar payloads com o tipo de varredura
payload_scan_type = {
    "<script>alert('XSS')</script>": "XSS Refletido",
    "\"'><script>alert('XSS')</script>": "XSS Refletido",
    "<img src=x onerror=alert('XSS')>": "XSS em Atributos HTML"
}

# Relacionar payloads ao OWASP Top 10
payload_owasp_category = {
    "<script>alert('XSS')</script>": "A7: Cross-Site Scripting (XSS)",
    "\"'><script>alert('XSS')</script>": "A7: Cross-Site Scripting (XSS)",
    "<img src=x onerror=alert('XSS')>": "A7: Cross-Site Scripting (XSS)"
}

# Função para enviar payloads de teste XSS e verificar vulnerabilidade
def test_xss_in_form(url, form_details, payload):
    """Testa um formulário enviando payload XSS nos campos"""
    from urllib.parse import urljoin

    # Constrói a URL correta se o "action" for relativo
    target_url = urljoin(url, form_details["action"]) if form_details["action"] else url
    method = form_details["method"]
    
    # Prepara os dados do formulário com o payload
    data = {}
    for input_detail in form_details["inputs"]:
        if input_detail["type"] == "text" or input_detail["type"] == "search":
            data[input_detail["name"]] = payload
        else:
            data[input_detail["name"]] = "test"  # Valores padrão para outros campos

    # Envia a requisição com base no método do formulário
    try:
        if method == "post":
            res = requests.post(target_url, data=data)
        else:
            res = requests.get(target_url, params=data)
        
        # Verifica se o payload aparece na resposta
        reflected_payload = payload in res.text

        # Verifica qual CVE está relacionada ao payload
        cve = payload_to_cve.get(payload, "N/A")

        result = {
            "url": target_url,
            "payload": payload,
            "status_code": res.status_code,
            "reflected_payload": reflected_payload,
            "cve": cve,
            "description": payload_descriptions.get(payload, "Descrição não disponível"),
            "scan_type": payload_scan_type.get(payload, "N/A"),
            "owasp_category": payload_owasp_category.get(payload, "N/A")
        }
        
        return result
    except requests.exceptions.RequestException as e:
        print(f"[!] Erro ao enviar requisição ao formulário: {e}")
        return None

# Função para exibir o relatório na CLI e gerar arquivo JSON completo
def print_report(results, url, method_counts, input_type_counts):
    """Imprime um relatório detalhado e gera JSON com todas as informações"""

    # Estrutura para o relatório JSON completo
    report_data = {
        "url_analisada": url,
        "metodos_http": method_counts,
        "tipos_entrada": input_type_counts,
        "total_itens_analisados": len(results),
        "detalhes_resultados": results
    }

    # Desenho do novo ASCII com o nome XSS-Scanner
    print("""
              ,---------------------------,            
              |  /---------------------\  |            
              | |                       | |            
              | |      XSS-SCANNER      | |            
              | |   Detecta e previne   | |            
              | |   vulnerabilidades    | |            
              | |                       | |                        
              |  \_____________________/  |            
              |___________________________|            
            ,---\_____     []     _______/------,      
          /         /______________\           /| ___     
        /___________________________________ /  |    )  
        |                                   |   |   ( 
        |  _ _ _                 [-------]  |   |    _)_  
        |  o o o                 [-------]  |  /    /''/ 
        |__________________________________ |/     /__/                                              
    """)

    # Exibir a URL com linhas horizontais como título na CLI
    print("\n" + "-" * 75)
    print(f"     URL analisada: {url}")
    print("-" * 75 + "\n")
    
    # Exibir métodos e tipos de entradas encontrados na CLI
    print("Métodos HTTP encontrados:")
    for method, count in method_counts.items():
        print(f"  - {method.upper()}: {count} formulário(s)")
    
    print("\nTipos de entrada encontradas:")
    for input_type, count in input_type_counts.items():
        print(f"  - {input_type}: {count} campo(s)")
    
    print(f"\nTotal de itens analisados: {len(results)}\n")


    # Primeira Tabela: Informações Gerais
    print("==== Informações Gerais sobre Payloads ====")
    print(f"{'Payload':<40} | {'Status HTTP':<12} | {'Refletido?':<10}")
    print("-" * 70)
    for result in results:
        if result:
            print(f"{result['payload']:<40} | "
                f"{result['status_code']:<12} | "
                f"{'Sim' if result['reflected_payload'] else 'Não':<10}")
        else:
             print(f"[!] Um erro ocorreu durante o teste de um formulário.")
    print("-" * 70)

    # Segunda Tabela: Detalhes Técnicos
    print("\n==== Detalhes Técnicos sobre Vulnerabilidades ====")
    print(f"{'CVE':<12} | {'OWASP Categoria':<25} | {'Varredura':<20} | {'Descrição Técnica':<50}")
    print("-" * 120)
    for result in results:
        if result:
             print(f"{result['cve']:<12} | "
                f"{result['owasp_category']:<25} | "
                f"{result['scan_type']:<20} | "
                f"{result['description']:<50}")
        else:
            print(f"[!] Um erro ocorreu durante o teste de um formulário.")
    print("-" * 120)


    # Gerar um nome de arquivo com data e hora
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = f"relatorio_{timestamp}.json"
    
    # Exportar o relatório como JSON
    with open(output_file, "w") as json_file:
        json.dump(report_data, json_file, indent=4)
    print(f"\n[+] Relatório exportado para: {output_file}")

    return output_file

# Função principal
if __name__ == "__main__":
    url = input("Digite a URL a ser analisada: ")
    
    # Tenta obter todos os formulários da URL
    forms = get_all_forms(url)
    if forms is None:
        print(f"[!] Não foi possível realizar a análise de segurança. Verifique a URL.")
    elif len(forms) == 0:
        print(f"[!] Nenhum formulário encontrado na URL: {url}")
    else:
        print(f"[+] Detectado {len(forms)} formulário(s) em {url}.\n")

        # Contadores para métodos HTTP e tipos de campos de entrada
        method_counts = Counter()
        input_type_counts = Counter()

        # Payloads XSS comuns para testar
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "\"'><script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
        ]

        results = []
        for i, form in enumerate(forms, start=1):
            form_details = get_form_details(form)
            print(f"Testando formulário #{i} em {form_details['action'] or 'URL raiz'}")
            
            # Contar o método HTTP
            method_counts[form_details["method"]] += 1
            
            # Contar tipos de entrada
            for input_detail in form_details["inputs"]:
                input_type_counts[input_detail["type"]] += 1

            # Testar os payloads de XSS
            for payload in xss_payloads:
                result = test_xss_in_form(url, form_details, payload)
                if result:
                    results.append(result)
        
        # Gera o relatório e salva automaticamente com timestamp
        output_file = print_report(results, url, method_counts, input_type_counts)

        # Perguntar se o usuário deseja abrir o dashboard
        open_dashboard = input("\nDeseja abrir o dashboard? (y/n): ").strip().lower()
        if open_dashboard == 'y':
            print("\n[+] Abrindo o dashboard...")
            os.system(f"streamlit run dashboard.py")
        else:
            print("[+] Dashboard não foi aberto.")
