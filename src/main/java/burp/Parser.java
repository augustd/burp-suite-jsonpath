package burp;

/**
 * Parses JSON response and creates JSONTab. 
 * 
 * @author August Detlefsen
 */
public class Parser {

	public String tabName;
	public String jsonToParse;
    private final IBurpExtenderCallbacks callbacks;
    private final JsonParserTab tab;

    public Parser(String tabName, String jsonToParse) {
		this.tabName = tabName;
		this.jsonToParse = jsonToParse;
        this.callbacks = BurpExtender.getCallbacks();
        this.tab = BurpExtender.getInstance().getParserTab();
    }

    public int parseJson() {
        try {
            callbacks.printOutput("JSON TO PARSE ----- \n" + jsonToParse);

            //parse the JSON
            JsonFormatter formatter = new JsonFormatter(jsonToParse);

            //initialize the GUI tab to display the results
            JsonEntry entry = new JsonEntry(formatter); 
            tab.createTab(tabName, entry);

        } catch (Exception e) {
            BurpExtender.getInstance().printStackTrace(e);
        }
        return 0;
    }
	
}
