import tomllib
import argparse

from markdownmaker.document import Document
from markdownmaker.markdownmaker import *

from header import headers_analysis_runner
from subdomain import subdomain_analysis_runner

def main():

    parser = argparse.ArgumentParser(description="Charybdis orchestrator")
    parser.add_argument("config", help="Path to common Charybdis configuration")
    args = parser.parse_args()
    try:
        with open(args.config, "rb") as file:
            config = tomllib.load(file)
    except FileNotFoundError:
        print(f"Configuration file {args.config} not found")
        return
    except tomllib.TOMLDecodeError:
        print(f"Error occured during TOML parsing {args.config}")
        return

    # Run headers analysis
    results = {}
    results["header_analysis"] = headers_analysis_runner(config)

    results["subdomain"] = subdomain_analysis_runner(config)

    generate_report(results)

def generate_report(results: dict):
    """
    Genrates Markdown report by given `results` dict of arrays of `Paragraphs` 
    """
    doc = Document()

    doc.add(Header("General"))

    doc.add(Header("Header analysis"))
    with HeaderSubLevel(doc):
        for paragraph in results["header_analysis"]["headers"]:
            doc.add(paragraph)

    doc.add(Header("Cookies analysis"))
    with HeaderSubLevel(doc):
        for paragraph in results["header_analysis"]["cookies"]:
            doc.add(paragraph)

    doc.add(Header("SQLmap results"))
    with HeaderSubLevel(doc):
        doc.add(results["header_analysis"]["sqlmap"])

    doc.add(Header("Subdomain search"))
    with HeaderSubLevel(doc):
        doc.add(results["subdomain"])

    with open("report.md", "w") as report:
        report.write(doc.write())

if __name__ == "__main__":
    main()