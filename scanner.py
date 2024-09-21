import requests
from bs4 import BeautifulSoup as bs
from collections import Counter

# Função para pegar todos os formulários de uma URL
def get_all_forms(url):
    """Captura todos os formulários de uma página web"""
    soup = bs(requests.get(url).content, "html.parser")
    return soup.find_all("form")

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

# Função para enviar payloads de teste XSS e verificar vulnerabilidade
def test_xss_in_form(url, form_details, payload):
    """Testa um formulário enviando payload XSS nos campos"""
    target_url = url if form_details["action"] is None or form_details["action"] == "" else form_details["action"]
    method = form_details["method"]
    
    # Prepara os dados do formulário com o payload
    data = {}
    for input_detail in form_details["inputs"]:
        if input_detail["type"] == "text" or input_detail["type"] == "search":
            data[input_detail["name"]] = payload
        else:
            data[input_detail["name"]] = "test"  # Valores padrão para outros campos

    # Envia a requisição com base no método do formulário
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
    }
    
    return result

# Função para exibir o relatório na CLI
def print_report(results, url, method_counts, input_type_counts):
    """Imprime um relatório detalhado com os resultados da análise na CLI"""
    
    # Desenho do novo ASCII com o nome XSS-Scanner
    print("""
              ,---------------------------,            
              |  /---------------------\  |            
              | |                       | |            
              | |        Relatório      | |            
              | |       gerado por:     | |            
              | |       XSS-SCANNER     | |            
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
               
                        
    --------------------------------------------------------------------------
    --------------------------------------------------------------------------
    """)

    # Exibir a URL
    print(f"URL analisada: {url}\n")
    
    # Exibir métodos e tipos de entradas encontrados
    print("Métodos HTTP encontrados:")
    for method, count in method_counts.items():
        print(f"  - {method.upper()}: {count} formulário(s)")
    
    print("\nTipos de entrada encontrados:")
    for input_type, count in input_type_counts.items():
        print(f"  - {input_type}: {count} campo(s)")
    
    print(f"\nTotal de formulários analisados: {len(results)}\n")

    # Cabeçalho da Tabela (sem a URL)
    print(f"{'Payload':<40} | {'Status HTTP':<12} | {'Refletido?':<10} | {'CVE':<12}")
    print("-" * 80)

    # Iterar por todos os resultados
    for result in results:
        print(f"{result['payload']:<40} | "
              f"{result['status_code']:<12} | "
              f"{'Sim' if result['reflected_payload'] else 'Não':<10} | "
              f"{result['cve']:<12}")
    print("-" * 80)

# Função principal
if __name__ == "__main__":
    url = input("Digite a URL a ser analisada: ")
    forms = get_all_forms(url)
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

    # Itera por todos os formulários e coleta detalhes de métodos e tipos de entrada
    for i, form in enumerate(forms, start=1):
        form_details = get_form_details(form)
        print(f"Testando formulário #{i} em {form_details['action'] or 'URL raiz'}")
        
        # Contar o método HTTP
        method_counts[form_details["method"]] += 1
        
        # Contar tipos de entrada
        for input_detail in form_details["inputs"]:
            input_type_counts[input_detail["type"]] += 1
        
        # Testar cada payload XSS no formulário
        for payload in xss_payloads:
            result = test_xss_in_form(url, form_details, payload)
            results.append(result)

    # Exibir o relatório na CLI
    print_report(results, url, method_counts, input_type_counts)
