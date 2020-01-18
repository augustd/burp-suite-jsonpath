package burp;

public class JsonEntry {

    private final String json;
    private final JsonFormatter formatter;

	public JsonEntry(JsonFormatter formatter) {
		this.formatter = formatter;
		this.json = formatter.prettyPrint();
	}

	public String getJson() {
		return json;
	}

	public JsonFormatter getFormatter() {
		return formatter;
	}
	
}
