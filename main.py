import requests
import argparse
from concurrent.futures import ThreadPoolExecutor
import concurrent.futures

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
            'small': 'small.txt',
            'medium': 'medium.txt',
            'large': 'large.txt'
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
                print(e)
        return 

    def saved_found_subdomains(self):
        file_name = 'subdomain_list.txt'
        with open(file_name, 'w') as f:
            for subdomain in self.found_subdomain:
                f.write(f"{subdomain} \n")
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
    domain = input("Введите домен второго уровня для поиска поддоменов: ").strip()
    proxies = []
    try:
        proxy_count = int(input("Введите количество прокси для использования (0, если не нужно): ").strip())
        if proxy_count > 0:
            print("Введите прокси в формате http://login:password@ip:port")
            for _ in range(proxy_count):
                proxy = input("Прокси: ").strip()
                proxies.append(proxy)
    except ValueError:
        print("Ошибка ввода. Прокси не заданы.")
    search_type = input("Выберите тип поиска (small, medium, large): ").strip().lower()
    if search_type not in ['small', 'medium', 'large']:
        print("Некорректный выбор. Установлен тип поиска 'small'.")
        search_type = 'small'

    finder = DomainFinder(domain=domain, proxies=proxies, search_type=search_type)
    finder.start()

if __name__ == '__main__':
    main()