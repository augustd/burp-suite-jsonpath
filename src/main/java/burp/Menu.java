package burp;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.List;
import java.util.Timer;

public class Menu implements IContextMenuFactory {

    private IExtensionHelpers helpers;
    private IBurpExtenderCallbacks callbacks;
    private IContextMenuInvocation invocation;
    private IHttpRequestResponse[] requestResponse;

    private JsonParserTab parserTab;
    public static Timer timer;

    public Menu(IBurpExtenderCallbacks callbacks, JsonParserTab parserTab) {
        helpers = callbacks.getHelpers();
        this.parserTab = parserTab;
        this.callbacks = callbacks;
        timer = new Timer();
    }

    @Override
    public List<JMenuItem> createMenuItems(final IContextMenuInvocation invocation) {

        this.invocation = invocation;
        
        //get information from the invocation
        IHttpRequestResponse[] ihrrs = invocation.getSelectedMessages();

        JMenuItem item = new JMenuItem("Parse JSON");
        item.addActionListener(new MenuItemListener(ihrrs));

        List<JMenuItem> list = new ArrayList<>();
        list.add(item);

        return list;
    }

    class MenuItemListener implements ActionListener {

        //private IHttpRequestResponse[] requestResponse;
        public MenuItemListener(IHttpRequestResponse[] ihrrs) {
            requestResponse = ihrrs;
        }

        @Override
        public void actionPerformed(ActionEvent ae) {
            Parser parser = new Parser(callbacks, helpers, parserTab);
            try {
                new Worker(parser, invocation, parserTab, callbacks).execute();
            } catch (Exception e1) {
                BurpExtender.getInstance().printStackTrace(e1);
            }
        }
    }

}
