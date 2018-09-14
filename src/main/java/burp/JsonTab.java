package burp;

import java.awt.*;
import java.util.ArrayList;
import java.util.List;

import javax.swing.*;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;

/**
 * Individual JSON tab, representing a single JsonEntry. Contains the pretty
 * print JSON and JSONPath search results.
 * 
 * @author August Detlefsen
 */
public class JsonTab implements IMessageEditorController {

    private final List<JsonEntry> entries = new ArrayList<>();
    private IHttpRequestResponse currentlyDisplayedItem;
    JSplitPane splitPane;
    JTabbedPane tabbedPane;

    public JsonTab(JTabbedPane tabbedPane, String request, JsonEntry entry) {
        this.tabbedPane = tabbedPane;

        //the right hand side displays the JSON Path panel
        JsonPathPanel jsonPathPanel = new JsonPathPanel(entry.json);

        //the left hand side displays the pretty print JSON
        DefaultListModel<JsonFormatter.PathTuple> listModel = new DefaultListModel<>();
        for (JsonFormatter.PathTuple tuple : entry.formatter.getLines()) {
            listModel.addElement(tuple);
        }
        JList<JsonFormatter.PathTuple> jsonList = new JList<>(listModel);
        jsonList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        jsonList.setLayoutOrientation(JList.VERTICAL);
        jsonList.addListSelectionListener(new JsonListSelectionListener(jsonList, jsonPathPanel)); 

        JScrollPane jsonPane = new JScrollPane(jsonList);

        //create the main left/right pane 
        splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        splitPane.setLeftComponent(jsonPane);
        splitPane.setRightComponent(jsonPathPanel);

        tabbedPane.add(request, splitPane);
    }
    
    class JsonListSelectionListener implements ListSelectionListener {

        private final JList<JsonFormatter.PathTuple> jsonList;
        private final JsonPathPanel jsonPathPanel;
        
        public JsonListSelectionListener(JList<JsonFormatter.PathTuple> jsonList, JsonPathPanel jsonPathPanel) {
            this.jsonList = jsonList;
            this.jsonPathPanel = jsonPathPanel;
        }
        
        @Override
        public void valueChanged(ListSelectionEvent e) {
            JsonFormatter.PathTuple selectedValue = jsonList.getSelectedValue();
            System.out.println("Selected: " + selectedValue);
            jsonPathPanel.setJsonPathEntry(selectedValue.path);
        }
    }

    public final void addEntry(JsonEntry entry) {
        synchronized (entries) {
            int row = entries.size();
            entries.add(entry);
            //fireTableRowsInserted(row, row);
            UIManager.put("tabbedPane.selected",
                    new javax.swing.plaf.ColorUIResource(Color.RED));
        }
    }

    public boolean containsEntry(byte[] message) {
        for (JsonEntry entry : entries) {
            if (message == entry.request) {
                return true;
            }
        }

        return false;
    }

    public JsonEntry getEntry(byte[] message) {
        for (JsonEntry entry : entries) {
            if (message == entry.request) {
                return entry;
            }
        }

        return null;
    }

    @Override
    public byte[] getRequest() {
        return currentlyDisplayedItem.getRequest();
    }

    @Override
    public byte[] getResponse() {
        return currentlyDisplayedItem.getResponse();
    }

    @Override
    public IHttpService getHttpService() {
        return currentlyDisplayedItem.getHttpService();
    }

}
