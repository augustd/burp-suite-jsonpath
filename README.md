# burp-suite-jsonpath
Burp Suite extension to view and extract data from JSON responses. 

### Parse
Parse and beautify JSON responses: 
![Parse JSON responses](screenshots/parse.png "Parse JSON responses")

### Query
Query JSON with [JSONPath](https://github.com/json-path/JsonPath) (clicking a field in the left hand column will pre-populate the JSONPath query): 
![Query with JSONPath](screenshots/query.png "Query with JSONPath")

### Copy
Copy query results for use in other tools (e.g. as Intruder payloads): 
![Copy results](screenshots/copy.png "Copy results")

### Multiple
Select multiple responses (e.g. from Intruder) and send them to the extension to query them together:
![Select multiple](screenshots/multiple_select.png "Select multiple")

Each JSON response will be combined into an array for easy querying:
![Select multiple](screenshots/multiple_results.png "Multiple results combined into an array")
