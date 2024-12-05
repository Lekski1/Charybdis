import logging
import requests
import tomllib
import argparse
from typing import List, Optional, Dict
from concurrent.futures import ThreadPoolExecutor, wait

from markdownmaker.markdownmaker import Paragraph

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

class DomainFinder:
    """
    A class to perform subdomain search using wordlists and proxies.
    """

    def __init__(self, domain: str, proxies: Optional[List[str]], search_type: str) -> None:
        self.domain = domain
        self.proxies = proxies or []
        self.search_type = search_type
        self.keyword = self.load_keywords()
        self.tasks = self.split_tasks()
        self.found_subdomains: List[str] = []

    def load_keywords(self) -> List[str]:
        """
        Load keywords from the wordlist file based on the search type.
        Returns:
            List[str]: A list of keywords.
        """
        file_map = {
            "demo": "word_list/demo.txt",
            "small": "word_list/small.txt",
            "medium": "word_list/medium.txt",
            "large": "word_list/large.txt",
        }
        filename = file_map.get(self.search_type)

        if not filename:
            logging.error(f"Invalid search type: {self.search_type}. Defaulting to 'small'.")
            filename = file_map["small"]

        try:
            with open(filename, "r") as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            logging.error(f"Wordlist file {filename} not found.")
            return []

    def split_tasks(self) -> List[List[str]]:
        """
        Split keywords into tasks based on the number of proxies.
        Returns:
            List[List[str]]: A list of keyword batches.
        """
        task_size = max(1, len(self.keyword) // max(1, len(self.proxies)))
        return [self.keyword[i:i + task_size] for i in range(0, len(self.keyword), task_size)]

    def search_domain(self, keywords: List[str], proxy: Optional[str]) -> None:
        """
        Search for subdomains using the given keywords and an optional proxy.
        Args:
            keywords (List[str]): Keywords for subdomain generation.
            proxy (Optional[str]): Proxy to use for requests.
        """
        for word in keywords:
            subdomain = f"{word}.{self.domain}"
            try:
                response = requests.get(f"http://{subdomain}", proxies={"http": proxy, "https": proxy} if proxy else None, timeout=5)
                if response.status_code == 200:
                    logging.info(f"Found: {subdomain}")
                    self.found_subdomains.append(subdomain)
            except requests.RequestException as e:
                logging.debug(f"Error checking {subdomain}: {e}")

    def save_found_subdomains(self) -> None:
        """
        Save found subdomains to a file.
        """
        file_name = "subdomain_list.txt"
        with open(file_name, "w") as f:
            for subdomain in self.found_subdomains:
                f.write(f"{subdomain}\n")
        logging.info(f"Found subdomains saved to {file_name}.")

    def start(self) -> None:
        """
        Start the subdomain search using multithreading.
        """
        with ThreadPoolExecutor(max_workers=len(self.proxies) or 4) as executor:
            futures = [
                executor.submit(self.search_domain, task, self.proxies[i] if self.proxies else None)
                for i, task in enumerate(self.tasks)
            ]
            wait(futures)
        self.save_found_subdomains()

def subdomain_analysis_runner(config: Dict) -> Dict[str, List[Paragraph]]:
    """
    Runner for subdomain analysis.
    Args:
        config (Dict): Configuration dictionary.
    Returns:
        Dict[str, List[Paragraph]]: Analysis results.
    """
    domain = config.get("general", {}).get("target_url", "")
    subdomain_conf = config.get("subdomain", {})

    result = {"subdomain": []}

    if not domain or not subdomain_conf.get("enable", False):
        logging.info("Subdomain analysis disabled or domain not specified.")
        return result

    proxies = []
    proxies_file = subdomain_conf.get("proxies_file")
    if proxies_file:
        try:
            with open(proxies_file, "r") as f:
                proxies = [line.strip() for line in f if line.strip() and not line.startswith("#")]
            logging.info(f"Loaded {len(proxies)} proxies from {proxies_file}.")
        except FileNotFoundError:
            logging.warning(f"Proxies file {proxies_file} not found. Proceeding without proxies.")

    search_type = subdomain_conf.get("search_type", "small")
    if search_type not in ["demo", "small", "medium", "large"]:
        logging.warning("Invalid search type in configuration. Defaulting to 'small'.")
        search_type = "small"

    finder = DomainFinder(domain=domain, proxies=proxies, search_type=search_type)
    finder.start()

    result["subdomain"] = [Paragraph("Subdomain search was successful.")]
    return result

def main() -> None:
    """
    Main function to execute the subdomain finder.
    """
    parser = argparse.ArgumentParser(description="Subdomain Finder")
    parser.add_argument("config", help="Path to the TOML configuration file")
    args = parser.parse_args()

    try:
        with open(args.config, "rb") as config_file:
            config = tomllib.load(config_file)
    except FileNotFoundError:
        logging.error(f"Configuration file {args.config} not found.")
        return
    except tomllib.TOMLDecodeError:
        logging.error(f"Error parsing TOML file {args.config}.")
        return

    subdomain_analysis_runner(config)

if __name__ == "__main__":
    main()