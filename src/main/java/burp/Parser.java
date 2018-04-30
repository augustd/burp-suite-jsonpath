package burp;

import com.codemagi.burp.Utils;
import com.codemagi.burp.parser.HttpRequest;
//import com.jayway.jsonpath.internal.JsonFormatter;

import javax.swing.*;
import java.net.URL;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class Parser {

    public static IExtensionHelpers helpers;
    public static IBurpExtenderCallbacks callbacks;
    public static IHttpRequestResponse httpRequestResponse;
    public static List<String> headers;
    //contains the (HashMap) structure of our built models
    private final Map<String, Map<String, Object>> hashModels = new HashMap<>();
    private final JsonParserTab tab;

    public Parser(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers, JsonParserTab tab) {
        Parser.callbacks = callbacks;
        Parser.helpers = helpers;
        this.tab = tab;
    }

    public int parseSwagger(IHttpRequestResponse requestResponse, IBurpExtenderCallbacks callbacks) {
        callbacks.printOutput("parseJson");
        httpRequestResponse = requestResponse;
        byte[] response = requestResponse.getResponse();

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
            JsonTab jsonTab = tab.createTab(requestPath, entry);

        } catch (Exception e) {
            BurpExtender.getInstance().printStackTrace(e);
        }
        return 0;
    }

}
