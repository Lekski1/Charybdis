# Charybdis: Domain Reconnaissance Tool

Charybdis is a Python-based tool designed to perform initial reconnaissance on a target domain, identifying potential vulnerabilities for subsequent penetration testing stages. The tool performs reconnaissance in three stages, providing a comprehensive security analysis of the target domain.

## Features

* **Security Header and Cookie Analysis:** Charybdis analyzes HTTP headers and cookies, identifying weaknesses in security configurations such as lack of XSS protection, Clickjacking vulnerabilities, and insecure cookie settings.
* **Subdomain Enumeration:** Charybdis performs third-level subdomain enumeration based on a wordlist provided in a text file, uncovering hidden sections of the target domain that may contain additional vulnerabilities. Supports the use of proxies to evade detection.
* **Port Scanning:** Charybdis offers flexible port scanning using `nmap` and/or `telnet`, allowing the user to choose between direct and stealth scanning. The tool identifies open ports and potential vulnerabilities (CVEs) associated with them. Also supports the use of proxies to obfuscate the scan origin.
* **Report Generation:** Charybdis generates a detailed report of the reconnaissance findings, including identified vulnerabilities and recommendations for remediation.

## Reconnaissance Stages

1. **Security Header and Cookie Analysis:**

    * Retrieval and analysis of HTTP headers.
    * Examination of cookie configurations and parameters defined by the website.
    * SQL injection probing (using additional tools).
    * Further investigation of potential vulnerabilities identified at this stage.

2. **Subdomain Enumeration:**

    * Brute-force enumeration of third-level subdomains based on the provided wordlist.
    * Utilization of proxy servers to prevent detection.

3. **Port Scanning:**

    * Research into `telnet` and `nmap` functionality to determine the optimal tool for stealth scanning.
    * Provision of a choice between direct and stealth scanning.
    * Identification of open ports and potential CVEs.
    * Utilization of proxy servers to mask the scan origin.


## Technologies

* **Programming Language:** Python
* **Build Tool:** Astral.sh (research)
* **Third-Party Code:** Open-Source only

***
# Charybdis: Инструмент первичной разведки доменов

Charybdis — это инструмент на Python, разработанный для проведения первичной разведки целевого домена, выявляя потенциальные уязвимости для последующих этапов тестирования на проникновение.  Инструмент выполняет разведку в три этапа, предоставляя всесторонний анализ безопасности целевого домена.

## Возможности

* **Анализ заголовков безопасности и куки:**  Charybdis анализирует HTTP-заголовки и куки, определяя слабые места в конфигурации безопасности, такие как отсутствие защиты от XSS, Clickjacking и небезопасные настройки куки.
* **Поиск поддоменов:** Charybdis выполняет поиск поддоменов третьего уровня, основанный на списке в текстовом файле, выявляя скрытые разделы целевого домена, которые могут содержать дополнительные уязвимости.  Поддерживает использование прокси для обхода обнаружения.
* **Сканирование портов:** Charybdis предлагает гибкое сканирование портов с использованием `nmap` и/или `telnet`, позволяя пользователю выбирать между прямым и скрытым сканированием.  Инструмент определяет открытые порты и потенциальные уязвимости, связанные с ними (CVE).  Также поддерживает использование прокси для скрытия источника сканирования.
* **Генерация отчетов:** Charybdis генерирует подробный отчет о результатах разведки, включая обнаруженные уязвимости и рекомендации по их устранению.

## Этапы разведки

1. **Анализ заголовков безопасности и куки:**

    * Получение и анализ HTTP-заголовков страницы.
    * Проверка конфигурации куки и параметров, определенных сайтом.
    * Поиск SQL-инъекций (с использованием дополнительных инструментов).
    * Дальнейшее исследование потенциальных уязвимостей на этом этапе.

2. **Поиск поддоменов:**

    * Перебор поддоменов третьего уровня на основе предоставленного списка.
    * Использование прокси-серверов для предотвращения обнаружения.

3. **Сканирование портов:**

    * Исследование работы `telnet` и `nmap` для определения оптимального инструмента для скрытого сканирования.
    * Предоставление выбора между прямым и скрытым сканированием.
    * Определение открытых портов и потенциальных CVE.
    * Использование прокси-серверов для скрытия источника сканирования.


## Технологии

* **Язык программирования:** Python
* **Средство сборки:** Astral.sh (исследование)
* **Сторонний код:** Только Open-Source

