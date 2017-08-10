package burp;

import com.codemagi.burp.Utils;
import com.codemagi.burp.parser.HttpRequest;
import com.jayway.jsonpath.internal.JsonFormatter;

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
            String prettyJson = JsonFormatter.prettyPrint(responseBody);
            callbacks.printOutput(prettyJson);
            
			//initialize the GUI tab to display the results
            JsonEntry entry = new JsonEntry(requestPath, response, "JSON", "JSON", requestResponse, prettyJson);
			JsonTab jsonTab = tab.createTab(requestPath, entry);
/*
			//create the subtabs
			Map<String, Path> paths = swagger.getPaths();
			for (String pathName : paths.keySet()) {
				Path path = paths.get(pathName);

				callbacks.printOutput("path: " + pathName);
				callbacks.printOutput(Json.pretty(path));

				URL pathUrl = new URL(url.getProtocol(), url.getHost(), url.getPort(), pathName);

				Map<HttpMethod, Operation> operations = path.getOperationMap();
				for (HttpMethod method : operations.keySet()) {
					String operationName = method.name();
					callbacks.printOutput("  method: " + operationName);
					callbacks.printOutput(Json.pretty(method));

					Operation op = operations.get(method);
					callbacks.printOutput("  op: " + op);
					callbacks.printOutput(Json.pretty(op));

					//create a request for this operation
					HttpRequest request = new HttpRequest(pathUrl, operationName);
					request.setHeader("Content-Type", Utils.getFirst(op.getConsumes()));
					request.setHeader("Accept", Utils.getFirst(op.getProduces()));
					request.setHeader("Origin", url.toString());

					//add the params
					List<Parameter> parameters = op.getParameters();
					for (Parameter p : parameters) {
						callbacks.printOutput("    param: " + Json.pretty(p));
						switch (p.getIn()) {
							case "query":
								request.setParameter(p.getName(), getDefaultValue(p));
								break;
							case "path":
								String requestPath = request.getPath();
								request.setPath(requestPath.replace("{" + p.getName() + "}", getDefaultValue(p)));
								break;
							case "body":
								request.setBody(getDefaultValue(p));
								break;
							case "header":
								request.setHeader(p.getName(), getDefaultValue(p));
								break;
							case "form":
								request.setParameter(p.getName(), getDefaultValue(p));
								request.convertToPost();
								break;
						}
					}

					callbacks.printOutput("REQUEST: " + request.toString());

					jsonTab.addEntry(new JsonEntry(pathName, request.getBytes(), operationName, op.getDescription(), requestResponse, Json.pretty(op)));
				}
			}
*/

        } catch (Exception e) {
			BurpExtender.getInstance().printStackTrace(e);
		}
		return 0;
	}
	
}
