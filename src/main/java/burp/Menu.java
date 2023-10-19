package burp;

import burp.ui.Worker;
import burp.ui.JsonParserTab;
import com.codemagi.burp.Utils;
import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Timer;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

public class Menu implements IContextMenuFactory {

    private final IExtensionHelpers helpers;
    private final IBurpExtenderCallbacks callbacks;
    private IContextMenuInvocation invocation;

    private final JsonParserTab parserTab;
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

        JMenuItem item = new JMenuItem("JSON Query");
        item.addActionListener(new MenuItemListener(invocation));

        List<JMenuItem> list = new ArrayList<>();
        list.add(item);

        return list;
    }

    class MenuItemListener implements ActionListener {

        private final IHttpRequestResponse[] requestResponses;
		private final IContextMenuInvocation invocation;

		public MenuItemListener(IContextMenuInvocation invocation) {
			this.invocation = invocation;
			this.requestResponses = invocation.getSelectedMessages();
		}
		
        @Override
        public void actionPerformed(ActionEvent ae) {
			callbacks.printOutput("actionPerformed");

			// Create an array to hold the JSON objects
			JsonArray jsonArray = new JsonArray();

			for (IHttpRequestResponse requestResponse : requestResponses) {
				//get the JSON to be parsed based on what was clicked
				byte[] message;
				boolean invocationIsResponse = true;
				switch (invocation.getInvocationContext()) {
					case IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST:
					case IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST:
						//get selection from request
						message = requestResponse.getRequest();
						invocationIsResponse = false;
						break;

					case IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_RESPONSE:
					case IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_RESPONSE:
					default:
						//get selection from message
						message = requestResponse.getResponse();
				}

				if (message == null) {
					JOptionPane.showMessageDialog(parserTab.getUiComponent().getParent(), "Can't Read Request/Response", "Error", JOptionPane.ERROR_MESSAGE);
					return;
				}

				//if a specific selection was made, use that
				String jsonToParse;
				int[] selection = invocation.getSelectionBounds();
				if (selection != null && selection[0] != selection[1]) {
					jsonToParse = Utils.getSelection(message, selection);
				} else {
					//use the full request or message body
					if (invocationIsResponse) {
						jsonToParse = new String(Utils.getResponseBody(message, helpers));
					} else {
						jsonToParse = new String(Utils.getRequestBody(message, helpers));
					}
				}

				JsonObject jsonObject1 = JsonParser.parseString(jsonToParse).getAsJsonObject();
				jsonArray.add(jsonObject1);
			}

			//get name for the new tab in the GUI
			String tabName = getRequestPath(requestResponses[0]);

			//create a new parser
            Parser parser = new Parser(tabName, jsonArray.toString());
            try {
                new Worker(parser, invocation).execute();
            } catch (Exception e1) {
                BurpExtender.getInstance().printStackTrace(e1);
            }
        }

		public String getRequestPath(IHttpRequestResponse requestResponse) {
			IRequestInfo requestInfo = helpers.analyzeRequest(requestResponse);
			
			URL url = requestInfo.getUrl();
			callbacks.printOutput("url: " + url.toString());
			
			String requestName = url.getHost();
			callbacks.printOutput("domain: " + requestName);
			
			return url.getPath();
		}
    }

}
