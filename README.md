# 🔍 XSS Scanner

🚀 **Ferramenta didática para detecção e mitigação de vulnerabilidades XSS (_Cross-Site Scripting_) em aplicações web.**  
Esta ferramenta automatiza o processo de análise de formulários presentes em uma página web, verificando se estão vulneráveis a ataques de XSS. Além de identificar potenciais falhas de segurança, o **XSS Scanner** oferece orientações sobre como mitigar as vulnerabilidades encontradas, ajudando desenvolvedores e estudantes a entender e proteger melhor suas aplicações.

---

## 🌟 Funcionalidades

✅ **Captura** todos os formulários de uma URL fornecida, permitindo uma análise abrangente da superfície de ataque.  
✅ **Testa** vulnerabilidades de XSS nos formulários, injetando *payloads* de teste comuns para detecção de _Cross-Site Scripting_.  
✅ **Exibe** um relatório detalhado, identificando formulários vulneráveis, status HTTP e se o *payload* foi refletido.  
✅ **Relaciona** vulnerabilidades encontradas a CVEs (Common Vulnerabilities and Exposures) conhecidos, explicando como cada falha pode ser explorada.  
✅ **Fornece recomendações práticas de mitigação** para fortalecer o código-fonte contra ataques XSS.

---

## 📚 Objetivo Educacional

O **XSS Scanner** não é apenas uma ferramenta de detecção, mas também um **instrumento didático**. Seu principal objetivo é ajudar desenvolvedores, estudantes de segurança da informação e profissionais da área a:

- Compreender a mecânica por trás dos ataques de XSS.
- Identificar rapidamente possíveis pontos de exploração em formulários web.
- Aprender as melhores práticas de mitigação e como aplicá-las diretamente no código front-end.

---

## 🛠️ Tecnologias Utilizadas

- **Python**: A linguagem utilizada para automatizar a análise.
- **Requests**: Para executar requisições HTTP de maneira simples e eficiente.
- **BeautifulSoup**: Para análise e extração de dados dos formulários no HTML.
- **Collections (Counter)**: Para contar e exibir o número de métodos HTTP e tipos de entrada encontrados nos formulários.
- **Colorama**: Para estilizar a saída no terminal, tornando o relatório mais legível e organizado.

---

## ✨ Melhorias Futuras

- Adicionar suporte a mais tipos de payloads XSS.
- Implementar interface gráfica para facilitar o uso.
- Análise mais detalhada de diferentes tipos de campos e suas vulnerabilidades.
- Adicionar exemplos de mitigação para mais linguagens (Java, PHP, etc.).

---