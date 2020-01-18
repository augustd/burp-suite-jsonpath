package burp.ui;

import burp.JsonEntry;
import burp.ui.JsonPathPanel;
import burp.ui.JsonDisplayPanel;
import javax.swing.*;

/**
 * Individual JSON tab, representing a single JsonEntry. Contains the pretty
 * print JSON and JSONPath search results.
 * 
 * @author August Detlefsen
 */
public class JsonTab extends JSplitPane {

    public JsonTab(String tabName, JsonEntry entry) {
		super(JSplitPane.HORIZONTAL_SPLIT);
		
        //the right hand side displays the JSON Path panel
        JsonPathPanel jsonPathPanel = new JsonPathPanel(entry.getJson());

        //the left hand side displays the pretty print JSON
		JsonDisplayPanel jsonPane = new JsonDisplayPanel(entry, jsonPathPanel);

        //create the main left/right pane 
		setLeftComponent(jsonPane);
		setRightComponent(jsonPathPanel);
		setDividerLocation(.5);
    }

}
