package burp.ui;

import burp.IBurpExtenderCallbacks;
import burp.ITab;
import burp.JsonEntry;
import com.codemagi.burp.ui.BurpTabbedPane;
import java.awt.*;
import java.util.ArrayList;

import javax.swing.*;

/**
 * The top level UI tab for the extension. Appears on the same row with Proxy, 
 * Repeater, etc and contains the individual parsed JSON tabs. 
 * 
 * @author August Detlefsen
 */
public class JsonParserTab extends java.awt.Component implements ITab {

    JTabbedPane tabbedPane;
    private final IBurpExtenderCallbacks callbacks;
    private final java.util.List<JsonTab> tabs = new ArrayList<>();

    public JsonParserTab(final IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;

        tabbedPane = new BurpTabbedPane();
		tabbedPane.addTab("...", new ArbitraryJsonPanel());

        callbacks.customizeUiComponent(tabbedPane);

        callbacks.addSuiteTab(JsonParserTab.this);
    }

    public JsonTab createTab(String tabName, JsonEntry entry) {

        JsonTab jsonTab = new JsonTab(tabName, entry);
		tabbedPane.add(tabName, jsonTab);
        tabbedPane.setSelectedIndex(tabbedPane.indexOfComponent(jsonTab)); 

        return jsonTab;
    }

    @Override
    public String getTabCaption() {
        return "JSON";
    }

    @Override
    public Component getUiComponent() {
        return tabbedPane;
    }
	
	public int getTabCount() {
		return tabbedPane.getTabCount();
	}

}
