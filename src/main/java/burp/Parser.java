package burp;

import com.codemagi.burp.Utils;

import javax.swing.*;
import java.net.URL;
import java.util.List;

/**
 * Parses JSON response and creates JSONTab. 
 * 
 * @author August Detlefsen
 */
public class Parser {

    public static IExtensionHelpers helpers;
    public static IBurpExtenderCallbacks callbacks;
    public static List<String> headers;
    private final JsonParserTab tab;

    public Parser(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers, JsonParserTab tab) {
        Parser.callbacks = callbacks;
        Parser.helpers = helpers;
        this.tab = tab;
    }

    public int parseJson(IHttpRequestResponse requestResponse, IBurpExtenderCallbacks callbacks) {
        callbacks.printOutput("parseJson");
        byte[] response = requestResponse.getResponse();

        //make sure we have a response to parse. If not, issue request again. 
        if (response == null) {
            IHttpRequestResponse request = callbacks.makeHttpRequest(requestResponse.getHttpService(), requestResponse.getRequest());
            response = request.getResponse();
        }
        if (response == null) {
            JOptionPane.showMessageDialog(tab.getUiComponent().getParent(), "Can't Read Response", "Error", JOptionPane.ERROR_MESSAGE);
            return -1;
        }

        IRequestInfo requestInfo = helpers.analyzeRequest(requestResponse);
        headers = requestInfo.getHeaders();
        callbacks.printOutput("got headers");

        URL url = requestInfo.getUrl();
        callbacks.printOutput("url: " + url.toString());

        String requestName = url.getHost();
        callbacks.printOutput("domain: " + requestName);

        String requestPath = url.getPath();

        try {
            String responseBody = new String(Utils.getResponseBody(response, helpers));
            callbacks.printOutput("RESPONSE BODY ----- \n" + responseBody);

            //parse the JSON
            JsonFormatter formatter = new JsonFormatter(responseBody);

            //initialize the GUI tab to display the results
            JsonEntry entry = new JsonEntry(requestPath, response, "JSON", "JSON", requestResponse, formatter);
            tab.createTab(requestPath, entry);

        } catch (Exception e) {
            BurpExtender.getInstance().printStackTrace(e);
        }
        return 0;
    }

}
