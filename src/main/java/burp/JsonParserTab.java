package burp;

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
    static int tabCount = 0;
    static int removedTabCount = 0;
    private final java.util.List<JsonTab> tabs = new ArrayList<>();

    public JsonParserTab(final IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;

        tabbedPane = new JTabbedPane();

        callbacks.customizeUiComponent(tabbedPane);

        callbacks.addSuiteTab(JsonParserTab.this);
    }

    public JsonTab createTab(String request, JsonEntry entry) {

        JsonTab jsonTab = new JsonTab(tabbedPane, request, entry);
        tabbedPane.setSelectedIndex(tabCount - removedTabCount);
        tabCount++;

        tabs.add(jsonTab);

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

    public boolean isJsonMessage(byte[] message) {
        for (JsonTab tab : tabs) {
            if (tab.containsEntry(message)) {
                return true;
            }
        }
        return false;
    }

    public String getJsonString(byte[] message) {
        for (JsonTab tab : tabs) {
            JsonEntry entry = tab.getEntry(message);
            if (entry != null) {
                return entry.json;
            }
        }
        return null;
    }
}
