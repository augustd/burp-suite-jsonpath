package burp;

public class JsonEntry {

    final String json;
    final JsonFormatter formatter;

	public JsonEntry(JsonFormatter formatter) {
		this.formatter = formatter;
		this.json = formatter.prettyPrint();
	}
	
}
