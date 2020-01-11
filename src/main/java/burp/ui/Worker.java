package burp.ui;

import burp.BurpExtender;
import burp.IContextMenuInvocation;
import burp.Menu;
import burp.Parser;
import java.awt.Color;
import java.util.TimerTask;
import javax.swing.JDialog;
import javax.swing.JProgressBar;
import javax.swing.JTabbedPane;
import javax.swing.SwingWorker;

/**
 * SwingWorker instance to allow JSON to be parsed in the background. 
 * 
 * @author August Detlefsen
 */
public class Worker extends SwingWorker<Void, Void> {

    private final JDialog dialog = new JDialog();
    private final Parser parser;
    private final IContextMenuInvocation invocation;
    private final JsonParserTab tab;
    private int status;

	public Worker(Parser parser) {
		this(parser, null);
	}
	
    public Worker(Parser parser, IContextMenuInvocation invocation) {
        this.tab = BurpExtender.getInstance().getParserTab();
        this.parser = parser;
        this.invocation = invocation;
        
		//pop a GUI progress bar
		JProgressBar progressBar = new JProgressBar();
        progressBar.setString("Parsing JSON");
        progressBar.setStringPainted(true);
        progressBar.setIndeterminate(true);
        dialog.getContentPane().add(progressBar);
        dialog.pack();
        dialog.setLocationRelativeTo(tab.getUiComponent().getParent());
        dialog.setModal(false);
        dialog.setVisible(true);
    }

    @Override
    protected Void doInBackground() throws Exception {
        status = parser.parseJson();
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
