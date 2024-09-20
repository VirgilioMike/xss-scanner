import requests
from bs4 import BeautifulSoup as bs

# Função para pegar todos os formulários de uma URL
def get_all_forms(url):
    """Captura todos os formulários de uma página web"""
    soup = bs(requests.get(url).content, "html.parser")
    return soup.find_all("form")

# Função para extrair os detalhes de cada formulário
def get_form_details(form):
    """Extrai os detalhes do formulário"""
    details = {}
    # O atributo "action" define para onde os dados do formulário serão enviados
    action = form.attrs.get("action")
    # O atributo "method" define o método HTTP usado (GET ou POST)
    method = form.attrs.get("method", "get").lower()
    # Extrair os campos de entrada
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        inputs.append({"type": input_type, "name": input_name})
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details

# Função principal
if __name__ == "__main__":
    url = input("Digite a URL a ser analisada: ")
    forms = get_all_forms(url)
    print(f"[+] Detectado {len(forms)} formulário(s) em {url}.\n")

    for i, form in enumerate(forms, start=1):
        form_details = get_form_details(form)
        print(f"Formulário #{i} detalhes:")
        print(f"  Action: {form_details['action']}")
        print(f"  Method: {form_details['method']}")
        print("  Inputs:")
        for input_detail in form_details["inputs"]:
            print(f"    - {input_detail['name']} ({input_detail['type']})")
        print("\n")
