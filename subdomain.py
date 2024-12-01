import requests
from concurrent.futures import ThreadPoolExecutor
import concurrent.futures
import argparse
import toml

class DomainFinder: 
    def __init__(self, domain, proxies, search_type):
        self.domain = domain 
        self.search_type = search_type
        self.proxies = proxies
        self.keyword = self.load_keyword()
        self.tasks = self.split_tasks()
        self.found_subdomain = []

    def split_tasks(self):
        task_size = max(1, len(self.keyword) // max(1, len(self.proxies)))
        tasks = []
        for i in range(0 , len(self.keyword), task_size):
            tasks.append(self.keyword[i:i + task_size])
        print(tasks)
        return tasks

    def load_keyword(self):
        file_map = {
            'small': '.word_list/small.txt',
            'medium': '.word_list/medium.txt',
            'large': '.word_list/large.txt'
        }
        filename = file_map.get(self.search_type)

        with open(filename, 'r') as f:
            word_list = []
            for line in f:
                if line.strip():
                    word_list.append(line.strip())

        return word_list

    def search_domain(self, keyword, proxy=None):
        for word in keyword: 
            subdomain = f"{word}.{self.domain}"
            try: 
                response = requests.get(f"http://{subdomain}", proxies={"http": proxy, "https": proxy} if proxy else None)
                if response.status_code == 200: 
                    print(f'Найден: {subdomain}')
                    self.found_subdomain.append(subdomain)
            except Exception as e: 
                print(f"Error: {e}")
        return 

    def saved_found_subdomains(self):
        file_name = 'subdomain_list.txt'
        with open(file_name, 'w') as f:
            for subdomain in self.found_subdomain:
                f.write(f"{subdomain}\n")
        print(f"\nНайденные поддомены сохранены в файл:", file_name)

    def start(self):
        with ThreadPoolExecutor(max_workers=len(self.proxies) or 4) as executer: 
            futures = []
            for number, keyword in enumerate(self.tasks):
                proxy = self.proxies[number] if self.proxies else None
                futures.append(executer.submit(self.search_domain, keyword, proxy))

            concurrent.futures.wait(futures)

        self.saved_found_subdomains()

def main():
    parser = argparse.ArgumentParser(description="Поиск поддоменов.")
    parser.add_argument("config", help="Путь к TOML файлу конфигурации")
    args = parser.parse_args()

    try:
        config = toml.load(args.config)
    except FileNotFoundError:
        print(f"Файл конфигурации {args.config} не найден.")
        return
    except toml.TomlDecodeError:
        print(f"Ошибка парсинга TOML файла {args.config}.")
        return


    domain = config.get("domain")
    proxies_file = config.get("proxies_file")
    search_type = config.get("search_type", "small") 

    if not domain:
        print("Домен не указан в конфигурационном файле.")
        return

    proxies = []
    if proxies_file:
        try:
            with open(proxies_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        proxies.append(line)
            print(f"Загружено {len(proxies)} прокси из файла {proxies_file}.")
        except FileNotFoundError:
            print(f"Файл {proxies_file} не найден. Прокси не будут использованы.")

    if search_type not in ["small", "medium", "large"]:
        print("Некорректный тип поиска в конфигурационном файле. Используется 'small'.")
        search_type = "small"


    finder = DomainFinder(domain=domain, proxies=proxies, search_type=search_type)
    finder.start()

if __name__ == '__main__':
    main()