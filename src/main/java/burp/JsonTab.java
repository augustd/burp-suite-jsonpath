package burp;

import java.awt.*;
import java.util.ArrayList;
import java.util.List;

import javax.swing.*;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableModel;

public class JsonTab extends AbstractTableModel implements IMessageEditorController {

    private String prettyJson;

    private final List<JsonEntry> entries = new ArrayList<>();
    private IMessageEditor requestViewer;
    private IHttpRequestResponse currentlyDisplayedItem;
    JSplitPane splitPane;
    JTabbedPane tabbedPane;

    private final IBurpExtenderCallbacks callbacks;

    public JsonTab(final IBurpExtenderCallbacks callbacks, JTabbedPane tabbedPane, String request, JsonEntry entry) {
        this.callbacks = callbacks;
        this.tabbedPane = tabbedPane;
        addEntry(entry);

        JTabbedPane tabs = new JTabbedPane();
        requestViewer = callbacks.createMessageEditor(this, false);
        tabs.addTab("Response", requestViewer.getComponent());

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
        tabbedPane.setTabComponentAt(JsonParserTab.tabCount - JsonParserTab.removedTabCount, new ButtonTabComponent(tabbedPane));

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
            fireTableRowsInserted(row, row);
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
    public int getRowCount() {
        return entries.size();
    }

    @Override
    public int getColumnCount() {
        return 3;
    }

    @Override
    public String getColumnName(int columnIndex) {
        switch (columnIndex) {
            case 0:
                return "Operation";
            case 1:
                return "Path";
            case 2:
                return "Description";
            default:
                return "";
        }
    }

    @Override
    public Class getColumnClass(int columnIndex) {
        return String.class;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {

        JsonEntry swaggerEntry = entries.get(rowIndex);

        switch (columnIndex) {
            case 0:
                return swaggerEntry.operationName;
            case 1:
                return swaggerEntry.path;
            case 2:
                return swaggerEntry.endpoints;
            default:
                return "";
        }
    }

    @Override
    public boolean isCellEditable(int row, int col) {
        return col >= 2;
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

    /**
     * Table previously displaying the list of swagger endpoints
     *
     * @deprecated
     */
    private class JsonTable extends JTable {

        public JsonTable(TableModel tableModel) {
            super(tableModel);
        }

        @Override
        public void changeSelection(int row, int col, boolean toggle, boolean extend) {

            JsonEntry swaggerEntry = entries.get(super.convertRowIndexToModel(row));
            requestViewer.setMessage(swaggerEntry.request, true);
            currentlyDisplayedItem = swaggerEntry.requestResponse;
            super.changeSelection(row, col, toggle, extend);
        }

        private boolean painted;

        @Override
        public void paint(Graphics g) {
            super.paint(g);

            if (!painted) {
                painted = true;
                splitPane.setResizeWeight(.30);
                splitPane.setDividerLocation(0.30);
            }
        }
    }

}
