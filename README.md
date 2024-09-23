## 🔷 XSS Scanner

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

---

### 🔍 **Ferramenta didática para detecção e mitigação de vulnerabilidades XSS (Cross-Site Scripting) em aplicações web.**  
O **XSS Scanner** automatiza o processo de análise de formulários em páginas web, detectando possíveis vulnerabilidades de _Cross-Site Scripting_ (XSS). Ideal para desenvolvedores, estudantes e profissionais de segurança da informação, a ferramenta identifica falhas de segurança e oferece orientações sobre como mitigá-las.

---

## 🔶 Funcionalidades

🔹 **Varredura de Formulários**: Analisa os formulários presentes na página web, capturando dados de todos os campos de entrada.  
🔹 **Teste de Vulnerabilidades XSS**: Injeção automática de *payloads* para detectar vulnerabilidades do tipo XSS, incluindo _Reflected_ e _Stored XSS_.  
🔹 **Relatório Detalhado**: Geração de um relatório com a identificação das vulnerabilidades, status HTTP e análise se o *payload* foi refletido.  
🔹 **CVEs Conhecidos**: Mapeamento de vulnerabilidades a CVEs (_Common Vulnerabilities and Exposures_) conhecidas.  
🔹 **Recomendações de Mitigação**: Sugestões claras de como corrigir as falhas de segurança encontradas, incluindo links para guias OWASP.

---

## 📚 Objetivo Educacional

O **XSS Scanner** tem um forte componente didático. Seu objetivo é **ensinar** ao mesmo tempo que detecta falhas. Ele é ideal para quem quer aprender sobre vulnerabilidades XSS de forma prática e aplicada. Ao utilizá-lo, você vai:

◾ Compreender a mecânica dos ataques XSS.  
◾ Identificar os pontos vulneráveis de sua aplicação web.  
◾ Aprender a aplicar as melhores práticas de segurança web.

---

## 🛠️ Tecnologias Utilizadas

- 🐍 **Python**: Automação do processo de análise.  
- 🌐 **Requests**: Manipulação eficiente de requisições HTTP.  
- 📝 **BeautifulSoup**: Extração de dados de formulários no HTML.  
- 🔢 **Collections (Counter)**: Contagem de métodos HTTP e tipos de entrada.  
- 🎨 **Colorama**: Melhorar a apresentação do relatório no terminal com cores e estilos.

---

## 🔷 Uso da Ferramenta

1. **Instalação das dependências**:
   ```bash
   pip install requests beautifulsoup4 colorama
   ```

2. **Execução da ferramenta**:
   Para rodar a análise em uma URL, execute:
   ```bash
   python scanner.py
   ```
   Após gerar o relatório, você será perguntado se deseja abrir o **dashboard**.

3. **Visualização do dashboard**:
   Após a análise, você pode visualizar o resultado no **dashboard** executando:
   ```bash
   streamlit run dashboard.py
   ```

---

## ✨ Melhorias Futuras

- ➕ Adicionar mais payloads XSS para ampliar a varredura.  
- 🎨 Desenvolver uma interface gráfica amigável.  
- 🔍 Análise mais aprofundada de campos de entrada e métodos de proteção.  
- 📘 Adicionar recomendações para múltiplas linguagens (PHP, Java, etc.).

---

## 📊 Relatório Gerado

A ferramenta gera um relatório em formato **JSON** que é alimentado no **dashboard** para visualização gráfica. O **dashboard** contém gráficos sobre a distribuição de payloads refletidos, vulnerabilidades por criticidade e um detalhamento técnico de cada falha encontrada.

---

## 📅 Exemplo de Uso

```bash
python scanner.py
```

Após a análise, você pode responder com "y" para abrir o **dashboard** automaticamente.

---

### 📝 Como Funciona:

1. **Captura de Formulários**: A ferramenta captura todos os formulários da página para análise.  
2. **Teste de Vulnerabilidades**: Os campos de entrada são testados com payloads XSS conhecidos.  
3. **Geração de Relatório**: Um relatório é gerado automaticamente, contendo informações detalhadas de vulnerabilidades encontradas.

---

## 🛡️ Exemplos de Recomendação de Mitigação

🔴 **CVE-2020-11022**: Vulnerabilidade de XSS no jQuery. Atualize para a versão mais recente do jQuery.  
🔴 **CVE-2019-11358**: Vulnerabilidade de XSS no jQuery. Recomenda-se atualizar para uma versão segura.  
🔴 **CVE-2020-7598**: XSS através de eventos em imagens (ex.: onerror). Evite usar diretamente atributos inseguros.

---

## 👥 Desenvolvedores

🔹 **Virgílio Oliveira**  
🔗 [LinkedIn - Virgílio Oliveira](https://www.linkedin.com/in/virgiliooliveira-/)

🔹 **Robson Damasceno**  
🔗 [LinkedIn - Robson Damasceno](https://www.linkedin.com/in/robson-damasceno/)

🔹 **Vitor Donnangelo**  
🔗 [LinkedIn - Vitor Donnangelo](https://www.linkedin.com/in/vitordonnangelo/)

---

### Exemplo de Saída do Relatório

```plaintext
URL analisada: https://exemplo.com
Métodos HTTP encontrados:
  - GET: 3 formulário(s)
  - POST: 2 formulário(s)

Tipos de entrada encontrados:
  - text: 4 campos
  - email: 2 campos

Total de itens analisados: 6
Proporção de payloads refletidos:
  - Refletido: 2
  - Não Refletido: 4

Distribuição de vulnerabilidades por criticidade:
  - Alta: 1
  - Média: 3
  - Baixa: 2
```

---

## 🔷 Escáner XSS (Español)

---

### 🔍 **Herramienta educativa para la detección y mitigación de vulnerabilidades XSS (Cross-Site Scripting) en aplicaciones web.**  
El **Escáner XSS** automatiza el proceso de análisis de formularios en páginas web, detectando posibles vulnerabilidades de _Cross-Site Scripting_ (XSS). Es ideal para desarrolladores, estudiantes y profesionales de la seguridad de la información, identificando fallas de seguridad y ofreciendo orientaciones sobre cómo mitigarlas.

---

## 🔶 Funcionalidades

🔹 **Escaneo de Formularios**: Analiza formularios presentes en la página web, capturando datos de todos los campos de entrada.  
🔹 **Prueba de Vulnerabilidades XSS**: Inyección automática de *payloads* para detectar vulnerabilidades del tipo XSS.  
🔹 **Informe Detallado**: Genera un informe con la identificación de las vulnerabilidades, el estado HTTP y si el *payload* fue reflejado.  
🔹 **CVEs Conocidos**: Mapeo de vulnerabilidades a CVEs (_Common Vulnerabilities and Exposures_) conocidos.  
🔹 **Recomendaciones de Mitigación**: Sugerencias claras de cómo corregir las fallas encontradas.

---

## 🛠️ Tecnologías Utilizadas

- 🐍 **Python**: Automatización del análisis.  
- 🌐 **Requests**: Manipulación eficiente de solicitudes HTTP.  
- 📝 **BeautifulSoup**: Extracción de datos de los formularios en HTML.  
- 🔢 **Collections (Counter)**: Contabilización de métodos HTTP y tipos de entrada.  
- 🎨 **Colorama**: Mejora de la presentación del informe en la terminal con colores y estilos.

---

## 📚 Objetivo Educativo

El **Escáner XSS** tiene un fuerte componente didáctico. Es ideal para aprender sobre vulnerabilidades XSS de manera práctica y aplicada. Al usarlo, aprenderás:

◾ Entender la mecánica de los ataques XSS.  
◾ Identificar los puntos vulnerables de tu aplicación web.  
◾ Aplicar las mejores prácticas de seguridad web.

---

## 👥 Desarrolladores

🔹 **Virgílio Oliveira**  
🔗 [LinkedIn - Virgílio Oliveira](https://www.linkedin.com/in/virgiliooliveira-/)

🔹 **Robson Damasceno**  
🔗 [LinkedIn - Robson Damasceno](https://www.linkedin.com/in/robson-damasceno/)

🔹 **Vitor Donnangelo**  
🔗 [LinkedIn - Vitor Donnangelo](https://www.linkedin.com/in/vitordonnangelo/)

angelo/)

---

## 🔷 XSS Scanner (English)

---

### 🔍 **Educational tool for detecting and mitigating XSS (Cross-Site Scripting) vulnerabilities in web applications.**  
The **XSS Scanner** automates the process of analyzing forms on web pages, detecting potential _Cross-Site Scripting_ (XSS) vulnerabilities. It is ideal for developers, students, and security professionals to identify security flaws and receive guidance on how to mitigate them.

---

## 🔶 Features

🔹 **Form Scanning**: Scans forms present on the web page, capturing data from all input fields.  
🔹 **XSS Vulnerability Testing**: Automatically injects payloads to detect XSS vulnerabilities.  
🔹 **Detailed Report**: Generates a report with vulnerability identification, HTTP status, and analysis of whether the payload was reflected.  
🔹 **Known CVEs**: Maps vulnerabilities to known CVEs (_Common Vulnerabilities and Exposures_).  
🔹 **Mitigation Recommendations**: Provides clear suggestions for how to fix security flaws, including links to OWASP guides.

---

## 🛠️ Technologies Used

- 🐍 **Python**: For automating the analysis process.  
- 🌐 **Requests**: Efficient HTTP request handling.  
- 📝 **BeautifulSoup**: Data extraction from forms in HTML.  
- 🔢 **Collections (Counter)**: Counting HTTP methods and input types.  
- 🎨 **Colorama**: Improves the terminal report presentation with colors and styles.

---

## 👥 Developers

🔹 **Virgílio Oliveira**  
🔗 [LinkedIn - Virgílio Oliveira](https://www.linkedin.com/in/virgiliooliveira-/)

🔹 **Robson Damasceno**  
🔗 [LinkedIn - Robson Damasceno](https://www.linkedin.com/in/robson-damasceno/)

🔹 **Vitor Donnangelo**  
🔗 [LinkedIn - Vitor Donnangelo](https://www.linkedin.com/in/vitordonnangelo/)

