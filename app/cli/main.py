import argparse
import sys

from pydantic import ValidationError

from ..config.settings import load_config, settings


def main():
    parser = argparse.ArgumentParser(description="DecryptTrace CLI")
    subparsers = parser.add_subparsers(dest="command")
    
    subparsers.add_parser("version", help="Show application version")
    subparsers.add_parser("health", help="Check application health")
    subparsers.add_parser("config-check", help="Validate configuration")
    
    args = parser.parse_args()
    
    if args.command == "version":
        print(f"{settings.app_name} v{settings.app_version} (Protocol {settings.protocol_version})")
    elif args.command == "health":
        print("System is healthy.")
    elif args.command == "config-check":
        try:
            cfg = load_config()
            print("Configuration is valid.")
            print(f"KEM: {cfg.kem_parameter}, Sig: {cfg.signature_parameter}")
        except ValidationError as e:
            print("Configuration invalid:")
            print(e)
            sys.exit(1)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
