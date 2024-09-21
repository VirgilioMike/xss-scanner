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

# Dicionário com explicações técnicas dos payloads
payload_descriptions = {
    "<script>alert('XSS')</script>": "Tenta executar um script de alerta simples usando a tag <script>.",
    "\"'><script>alert('XSS')</script>": "Quebra a estrutura HTML e injeta um script malicioso.",
    "<img src=x onerror=alert('XSS')>": "Injeta código malicioso usando evento de erro em imagem."
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
        "description": payload_descriptions.get(payload, "Descrição não disponível")
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

    # Exibir a URL com linhas horizontais como título
    print("\n" + "-" * 75)
    print(f"     URL analisada: {url}")
    print("-" * 75 + "\n")
    
    # Exibir métodos e tipos de entradas encontrados
    print("Métodos HTTP encontrados:")
    for method, count in method_counts.items():
        print(f"  - {method.upper()}: {count} formulário(s)")
    
    print("\nTipos de entrada encontradas:")
    for input_type, count in input_type_counts.items():
        print(f"  - {input_type}: {count} campo(s)")
    
    print(f"\nTotal de itens analisados: {len(results)}\n")

    # Cabeçalho da Tabela com a coluna de Descrição Técnica
    print(f"{'Payload':<40} | {'Status HTTP':<12} | {'Refletido?':<10} | {'CVE':<12} | {'Descrição Técnica':<50}")
    print("-" * 140)

    # Iterar por todos os resultados
    for result in results:
        print(f"{result['payload']:<40} | "
              f"{result['status_code']:<12} | "
              f"{'Sim' if result['reflected_payload'] else 'Não':<10} | "
              f"{result['cve']:<12} | "
              f"{result['description']:<50}")
    print("-" * 140)

    # Adicionar uma breve recomendação para mitigação com exemplos práticos
    print("""
    Mitigação:
    
    CVE-2020-11022. 
    Escapar adequadamente o conteúdo dinâmico:
    Sempre escape o conteúdo dinâmico que será renderizado em HTML, JavaScript ou CSS. Isso garante que qualquer dado fornecido pelo usuário seja tratado como texto, e não como código executável.
       
       Exemplo em Python (Flask):
       ```python
       from flask import escape

       @app.route('/safe')
       def safe():
           user_input = request.args.get('user_input', '')
           return f"Olá, {escape(user_input)}!"
       ```

    CVE-2019-11358. 
    Utilizar Content Security Policy (CSP):
    A CSP ajuda a prevenir a execução de scripts maliciosos, restringindo quais fontes de conteúdo (como scripts, imagens, etc.) são permitidas no site.
       
       Exemplo de configuração de CSP no cabeçalho HTTP:
       ```plaintext
       Content-Security-Policy: default-src 'self'; script-src 'self' https://apis.google.com
       ```

    CVE-2020-7598. 
    Validar e higienizar todas as entradas dos usuários:
    Antes de processar dados de entrada, é fundamental validá-los para garantir que eles não contenham scripts maliciosos. Isso pode ser feito filtrando caracteres especiais e verificando o formato dos dados.

       Exemplo de sanitização em JavaScript:
       ```javascript
       function sanitizeInput(input) {
           return input.replace(/</g, "&lt;").replace(/>/g, "&gt;");
       }

       // Uso:
       var userInput = sanitizeInput("<script>alert('XSS')</script>");
       ```
    """)

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
