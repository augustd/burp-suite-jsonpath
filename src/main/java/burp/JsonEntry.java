package burp;

public class JsonEntry {

    final String path;
    final byte[] request;
    final String operationName;
    final IHttpRequestResponse requestResponse;
    final String endpoints;
    final String json;
    final JsonFormatter formatter;

    JsonEntry(String bindingName, byte[] request, String operationName, String endpoints, IHttpRequestResponse requestResponse, JsonFormatter formatter) {
        this.path = bindingName;
        this.request = request;
        this.operationName = operationName;
        this.endpoints = endpoints;
        this.requestResponse = requestResponse;
        this.formatter = formatter;
        this.json = formatter.prettyPrint();
    }

}
