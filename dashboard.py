import json
import streamlit as st
import plotly.express as px
import os
from glob import glob

# Função para pegar o último arquivo JSON criado
def get_latest_json_file(directory="."):
    json_files = glob(os.path.join(directory, "*.json"))
    if not json_files:
        return None
    latest_file = max(json_files, key=os.path.getctime)  # Ordena pelo tempo de criação
    return latest_file

# Função para calcular a criticidade com base nos CVEs (usando pontuação CVSS)
def calculate_risk_index(cve_list):
    risk_score = 0
    cvss_scores = {
        "CVE-2020-11022": 7.5,  # Alta criticidade
        "CVE-2019-11358": 6.0,  # Média criticidade
        "CVE-2020-7598": 5.5    # Média criticidade
    }
    for cve in cve_list:
        risk_score += cvss_scores.get(cve, 0)  # Se CVE não estiver no dicionário, assume-se 0
    return risk_score / len(cve_list) if cve_list else 0

# Função para classificar criticidade (baixa, média, alta) com base na pontuação CVSS
def classify_severity(cve):
    cvss_scores = {
        "CVE-2020-11022": 7.5,  # Alta criticidade
        "CVE-2019-11358": 6.0,  # Média criticidade
        "CVE-2020-7598": 5.5    # Média criticidade
    }
    score = cvss_scores.get(cve, 0)
    if score >= 7.0:
        return "Alta"
    elif score >= 4.0:
        return "Média"
    else:
        return "Baixa"

# Função para gerar recomendações baseadas no CVE
def get_recommendations(cve):
    recommendations = {
        "CVE-2020-11022": "Vulnerabilidade de XSS no jQuery. Atualize para a versão mais recente do jQuery. Veja detalhes <a href='https://nvd.nist.gov/vuln/detail/CVE-2020-11022' target='_blank'>aqui</a>.",
        "CVE-2019-11358": "Vulnerabilidade de XSS no jQuery. Recomenda-se atualizar o jQuery para uma versão segura. Veja detalhes <a href='https://nvd.nist.gov/vuln/detail/CVE-2019-11358' target='_blank'>aqui</a>.",
        "CVE-2020-7598": "Vulnerabilidade de XSS através de eventos em imagens (ex.: onerror). Evite usar diretamente atributos inseguros. Veja detalhes <a href='https://nvd.nist.gov/vuln/detail/CVE-2020-7598' target='_blank'>aqui</a>."
    }
    return recommendations.get(cve, "Recomendação não disponível para este CVE.")

# Título do dashboard
st.title("Dashboard de Segurança XSS")

# Procurar automaticamente o último arquivo JSON gerado
latest_json_file = get_latest_json_file()

if latest_json_file:
    st.write(f"Carregando o arquivo mais recente: {latest_json_file}")
    
    try:
        # Carregar o arquivo JSON mais recente
        with open(latest_json_file) as f:
            data = json.load(f)

        # Cabeçalho estruturado em formato de tabela
        st.header("Resumo Geral")

        # Contar vulnerabilidades críticas com base nos CVEs
        critical_vulns = [result for result in data['detalhes_resultados'] if result['cve'] is not None]

        # Calcular índice de risco baseado no CVSS
        cve_list = [result["cve"] for result in data["detalhes_resultados"]]
        risk_index = calculate_risk_index(cve_list)

        # Contadores de métodos HTTP
        method_counts = {"GET": 0, "POST": 0, "OUTROS": 0}

        # Coletar dados de métodos
        for result in data['detalhes_resultados']:
            method = result.get('method', 'OUTROS').upper()
            if method in method_counts:
                method_counts[method] += 1
            else:
                method_counts['OUTROS'] += 1

        # Organizando os dados em uma tabela
        table_data = {
            "Resumo Geral": ["URL Analisada", "Total de Formulários Analisados", "Total de Vulnerabilidades", 
                             "Vulnerabilidades Críticas", "Índice de Risco Geral", "Métodos HTTP"],
            "Valor": [
                data['url_analisada'], 
                len(data['detalhes_resultados']), 
                len(critical_vulns),
                f"Alta: {len([v for v in critical_vulns if classify_severity(v['cve']) == 'Alta'])}, "
                f"Média: {len([v for v in critical_vulns if classify_severity(v['cve']) == 'Média'])}, "
                f"Baixa: {len([v for v in critical_vulns if classify_severity(v['cve']) == 'Baixa'])}",
                f"{risk_index:.1f}/10",
                f"GET: {method_counts['GET']}, POST: {method_counts['POST']}, Outros: {method_counts['OUTROS']}"
            ]
        }

        # Exibir a tabela formatada
        st.table(table_data)

        # Insights Gráficos
        st.header("Insights Gráficos")

        # Gráfico de Proporção de Payloads Refletidos
        reflected_payloads = [res['reflected_payload'] for res in data['detalhes_resultados']]
        fig_reflected = px.pie(
            names=["Refletido", "Não Refletido"],
            values=[reflected_payloads.count(True), reflected_payloads.count(False)],
            title="Proporção de Payloads Refletidos",
            color_discrete_sequence=["#3498DB", "#BDC3C7"]  # Azul para refletido, cinza para não refletido
        )
        st.plotly_chart(fig_reflected, use_container_width=True)

        # Gráfico de Vulnerabilidades por Criticidade
        severity_counts = {"Alta": 0, "Média": 0, "Baixa": 0}
        for result in data['detalhes_resultados']:
            severity = classify_severity(result['cve'])
            severity_counts[severity] += 1

        fig_severity = px.bar(
            x=list(severity_counts.keys()),  # Alta, Média, Baixa
            y=list(severity_counts.values()),  # Contagem de vulnerabilidades
            title="Distribuição de Vulnerabilidades por Criticidade",
            color=list(severity_counts.keys()),
            color_discrete_map={"Alta": "#E74C3C", "Média": "#F39C12", "Baixa": "#F1C40F"}  # Vermelho, Laranja, Amarelo
        )
        st.plotly_chart(fig_severity, use_container_width=True)

        # Detalhamento Técnico e Recomendações
        st.header("Detalhamento Técnico e Recomendações")

        # Ordenar os resultados pela criticidade (Alta -> Média -> Baixa)
        severity_order = {"Alta": 0, "Média": 1, "Baixa": 2}
        sorted_results = sorted(data['detalhes_resultados'], key=lambda res: severity_order[classify_severity(res['cve'])])

        # Mapeamento de cores para as bolinhas
        color_map = {"Alta": "#E74C3C", "Média": "#F39C12", "Baixa": "#F1C40F"}

        for idx, result in enumerate(sorted_results, 1):
            # Obter a criticidade do item
            criticidade = classify_severity(result['cve'])

            # Bolinha colorida indicando a criticidade
            bolinha_html = f"<span style='color:{color_map[criticidade]};font-size:20px;'>&#9679;</span>"

            # Adicionar a criticidade ao título do item
            st.markdown(
                f"""
                {bolinha_html} **Item #{idx} [{criticidade}] - {result['scan_type']}**
                """,
                unsafe_allow_html=True
            )
            st.write(f"**Payload:** {result['payload']}")  # Payload como texto
            st.write(f"**Status HTTP:** {result['status_code']}")
            st.write(f"**Payload Refletido:** {'Sim' if result['reflected_payload'] else 'Não'}")
            st.write(f"**CVE:** {result['cve']}")
            st.write(f"**Descrição:** {result['description']}")
            st.write(f"**OWASP Categoria:** {result.get('owasp_category', 'Categoria OWASP não disponível')}")
            
            # Adicionar recomendações com base no CVE
            st.markdown(
                f"""
                <div style='background-color:#2c3e50;padding:10px;border-radius:5px;color:#ecf0f1;'>
                    🔴 {get_recommendations(result['cve'])}
                </div>
                """,
                unsafe_allow_html=True
            )

            # Adicionar uma linha para separar os itens
            st.markdown("---")

    except FileNotFoundError:
        st.error(f"Arquivo {latest_json_file} não encontrado. Por favor, verifique o nome e tente novamente.")

else:
    st.error("Nenhum arquivo JSON encontrado no diretório.")
