from app import create_app
import argparse
import logging

def main():
    """Main entry point for the application."""
    parser = argparse.ArgumentParser(description='Code Security Analyzer')
    parser.add_argument('--host', default='127.0.0.1', help='Host to bind the web server')
    parser.add_argument('--port', type=int, default=5000, help='Port to bind the web server')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    args = parser.parse_args()

    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('app.log'),
            logging.StreamHandler()
        ]
    )

    # Create and run the application
    app = create_app()
    app.run(host=args.host, port=args.port, debug=args.debug)

if __name__ == '__main__':
    main() 