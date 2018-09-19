package burp;

import javax.swing.*;

/**
 * Individual JSON tab, representing a single JsonEntry. Contains the pretty
 * print JSON and JSONPath search results.
 * 
 * @author August Detlefsen
 */
public class JsonTab {

    JSplitPane splitPane;
    JTabbedPane tabbedPane;

    public JsonTab(JTabbedPane tabbedPane, String request, JsonEntry entry) {
        this.tabbedPane = tabbedPane;

        //the right hand side displays the JSON Path panel
        JsonPathPanel jsonPathPanel = new JsonPathPanel(entry.json);

        //the left hand side displays the pretty print JSON
		JsonDisplayPanel jsonPane = new JsonDisplayPanel(entry, jsonPathPanel);

        //create the main left/right pane 
        splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        splitPane.setLeftComponent(jsonPane);
        splitPane.setRightComponent(jsonPathPanel);
		splitPane.setDividerLocation(.5);

        tabbedPane.add(request, splitPane);
    }

}
