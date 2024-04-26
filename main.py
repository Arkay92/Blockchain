import logging
from test import main as test_main

def main():
    try:
        test_main()

    except Exception as e:
        logging.exception("An error occurred", exc_info=e)
        raise

if __name__ == '__main__':
    main()