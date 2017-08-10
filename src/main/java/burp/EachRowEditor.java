package burp;

import java.awt.*;
import java.awt.event.MouseEvent;
import java.util.EventObject;
import java.util.HashMap;

import javax.swing.*;
import javax.swing.event.CellEditorListener;
import javax.swing.table.TableCellEditor;

class EachRowEditor implements TableCellEditor {

    protected HashMap editors;
    protected TableCellEditor editor, defaultEditor;
    JTable table;

    /**
     * Constructs a EachRowEditor. create default editor
     *
     * @see javax.swing.table.TableCellEditor
     * @see javax.swing.DefaultCellEditor
     */
    public EachRowEditor(JTable table) {
        this.table = table;
        editors = new HashMap();
        defaultEditor = new DefaultCellEditor(new JComboBox());
    }

    /**
     * @param row    table row
     * @param editor table cell editor
     */
    public void setEditorAt(int row, TableCellEditor editor) {
        editors.put(row, editor);
    }

	@Override
    public Component getTableCellEditorComponent(JTable table, Object value,
                                                 boolean isSelected, int row, int column) {

        return editor.getTableCellEditorComponent(table, value, isSelected,
                row, column);
    }


	@Override
    public Object getCellEditorValue() {
        return editor.getCellEditorValue();
    }

	@Override
    public boolean stopCellEditing() {
        return editor.stopCellEditing();
    }

	@Override
    public void cancelCellEditing() {
        editor.cancelCellEditing();
    }

	@Override
    public boolean isCellEditable(EventObject anEvent) {
        selectEditor((MouseEvent) anEvent);
        return editor.isCellEditable(anEvent);
    }

	@Override
    public void addCellEditorListener(CellEditorListener l) {
        editor.addCellEditorListener(l);
    }

	@Override
    public void removeCellEditorListener(CellEditorListener l) {
        editor.removeCellEditorListener(l);
    }

	@Override
    public boolean shouldSelectCell(EventObject anEvent) {
        selectEditor((MouseEvent) anEvent);
        return editor.shouldSelectCell(anEvent);
    }

    protected void selectEditor(MouseEvent e) {
        int row;
        if (e == null) {
            row = table.getSelectionModel().getAnchorSelectionIndex();
        } else {
            row = table.rowAtPoint(e.getPoint());
        }
        editor = (TableCellEditor) editors.get(row);
        if (editor == null) {
            editor = defaultEditor;
        }
    }
}
