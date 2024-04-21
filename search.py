import json
import logging

def search_logs(query):
    try:
        with open("all_logs.json", "r") as file:
            logs = json.load(file)
    except FileNotFoundError:
        logging.error("Log file not found.")
        return []
    except json.JSONDecodeError as e:
        logging.error(f"Error decoding JSON: {e}")
        return []

    search_results = []
    for log in logs:
        # Perform case-insensitive search in log fields
        if any(query.lower() in str(value).lower() for value in log.values()):
            search_results.append(log)

    if not search_results:
        logging.info(f"No search results found for '{query}'.")
    else:
        logging.info("Search Results:")
        for result in search_results:
            logging.info(result)

    return search_results

def main():
    logging.basicConfig(level=logging.INFO)

    # Prompt user for search query
    query = input("Enter search query: ")

    # Perform search
    search_results = search_logs(query)

    # Display search results
    if not search_results:
        print(f"No search results found for '{query}'.")
    else:
        print("Search Results:")
        for result in search_results:
            print(result)

if __name__ == "__main__":
    main()
