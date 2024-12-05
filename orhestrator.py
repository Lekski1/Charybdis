import tomllib
import argparse
import logging

from markdownmaker.document import Document
from markdownmaker.markdownmaker import Header, HeaderSubLevel

from header import headers_analysis_runner
from subdomain import subdomain_analysis_runner
from telnet import telnet_runner
from nmap import nmap_runner

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def main():
    """
    Entry point for the Charybdis orchestrator.
    Parses the configuration file, executes analysis modules, and generates a report.
    """
    parser = argparse.ArgumentParser(description="Charybdis Orchestrator")
    parser.add_argument("config", help="Path to the Charybdis configuration file")
    args = parser.parse_args()

    # Load configuration
    try:
        config = load_config(args.config)
    except (FileNotFoundError, tomllib.TOMLDecodeError) as e:
        logging.error(e)
        return

    # Run analysis modules
    results = {
        "nmap": nmap_runner(config),
        "telnet": telnet_runner(config),
        "subdomain": subdomain_analysis_runner(config),
        "header_analysis": headers_analysis_runner(config),
    }

    # Generate and save the report
    try:
        generate_report(results, "report.md")
        logging.info("Report successfully generated and saved as 'report.md'.")
    except Exception as e:
        logging.error(f"Failed to generate report: {e}")

def load_config(config_path: str) -> dict:
    """
    Loads the TOML configuration file.

    Args:
        config_path (str): Path to the configuration file.

    Returns:
        dict: Parsed configuration data.

    Raises:
        FileNotFoundError: If the file is not found.
        tomllib.TOMLDecodeError: If the file contains invalid TOML.
    """
    try:
        with open(config_path, "rb") as file:
            logging.info(f"Loading configuration from {config_path}")
            return tomllib.load(file)
    except FileNotFoundError:
        raise FileNotFoundError(f"Configuration file '{config_path}' not found.")
    except tomllib.TOMLDecodeError:
        raise tomllib.TOMLDecodeError(f"Error occurred during TOML parsing of '{config_path}'.")

def generate_report(results: dict, output_file: str):
    """
    Generates a Markdown report from the analysis results.

    Args:
        results (dict): A dictionary of analysis results.
        output_file (str): Path to save the generated report.

    Raises:
        Exception: If an error occurs during report generation or saving.
    """
    doc = Document()

    doc.add(Header("Charybdis Analysis Report"))

    doc.add(Header("Header Analysis"))
    with HeaderSubLevel(doc):
        for paragraph in results["header_analysis"].get("headers", []):
            doc.add(paragraph)

    doc.add(Header("Cookies Analysis"))
    with HeaderSubLevel(doc):
        for paragraph in results["header_analysis"].get("cookies", []):
            doc.add(paragraph)

    doc.add(Header("SQLmap Results"))
    with HeaderSubLevel(doc):
        sqlmap_result = results["header_analysis"].get("sqlmap", "No results available.")
        doc.add(sqlmap_result)

    doc.add(Header("Subdomain Search"))
    with HeaderSubLevel(doc):
        subdomain_result = results.get("subdomain", "No results available.")
        for paragraph in subdomain_result:
            doc.add(paragraph)

    doc.add(Header("Telnet Scan"))
    with HeaderSubLevel(doc):
        telnet_result = results["telnet"].get("telnet", "No results available.")
        doc.add(telnet_result)

    doc.add(Header("Nmap Scan"))
    with HeaderSubLevel(doc):
        nmap_result = results["nmap"].get("nmap", "No results available.")
        for paragraph in nmap_result:
            doc.add(paragraph)

    # Save the report to a file
    with open(output_file, "w", encoding="utf-8") as report_file:
        report_file.write(doc.write())
        logging.info(f"Report saved to '{output_file}'.")

if __name__ == "__main__":
    main()
