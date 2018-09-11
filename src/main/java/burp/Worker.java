package burp;

import java.awt.Color;
import java.util.TimerTask;
import javax.swing.JDialog;
import javax.swing.JProgressBar;
import javax.swing.JTabbedPane;
import javax.swing.SwingWorker;

/**
 * SwingWorker instance to allow JSON t be parsed in the background. 
 * 
 * @author August Detlefsen
 */
class Worker extends SwingWorker<Void, Void> {

    private final JDialog dialog = new JDialog();
    private final Parser parser;
    private final IContextMenuInvocation invocation;
    private final JsonParserTab tab;
    private final IBurpExtenderCallbacks callbacks;
    private int status;

    public Worker(Parser parser, IContextMenuInvocation invocation, JsonParserTab tab, IBurpExtenderCallbacks callbacks) {
        JProgressBar progressBar = new JProgressBar();
        progressBar.setString("Parsing JSON");
        progressBar.setStringPainted(true);
        progressBar.setIndeterminate(true);
        dialog.getContentPane().add(progressBar);
        dialog.pack();
        dialog.setLocationRelativeTo(tab.getUiComponent().getParent());
        dialog.setModal(false);
        dialog.setVisible(true);
        this.parser = parser;
        this.invocation = invocation;
        this.tab = tab;
        this.callbacks = callbacks;
    }

    @Override
    protected Void doInBackground() throws Exception {
        status = parser.parseJson(invocation.getSelectedMessages()[0], callbacks);
        return null;
    }

    @Override
    protected void done() {
        dialog.dispose();
        if (status >= 0) {
            final JTabbedPane parent = (JTabbedPane) tab.getUiComponent().getParent();
            final int index = parent.indexOfComponent(tab.getUiComponent());
            parent.setBackgroundAt(index, new Color(229, 137, 1));

            Menu.timer.schedule(new TimerTask() {
                @Override
                public void run() {
                    parent.setBackgroundAt(index, new Color(0, 0, 0));
                }
            }, 5000);

        }
    }
}
