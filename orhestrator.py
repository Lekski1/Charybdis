import tomllib
import argparse

from header import headers_analysis_runner

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
    header_results = headers_analysis_runner(config) 
    



if __name__ == "__main__":
    main()