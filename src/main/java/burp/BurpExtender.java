package burp;

import com.codemagi.burp.BaseExtender;

/**
 * JSON Path: A BurpSuite extension to parse JSON responses and enable searching
 * for specific elements using JSON Path expression language
 *
 * @author augustd
 */
public class BurpExtender extends BaseExtender implements IBurpExtender, IMessageEditorTabFactory {

    public static final String TAB_NAME = "JSON";
    public static final String EXTENSION_NAME = "JSON Path";
    private static BurpExtender instance;
    private JsonParserTab parserTab;

    @Override
    protected void initialize() {
        extensionName = EXTENSION_NAME;

        parserTab = new JsonParserTab(callbacks);

        callbacks.registerContextMenuFactory(new Menu(callbacks, parserTab));

        // register ourselves as a message editor tab factory
        callbacks.registerMessageEditorTabFactory(this);

        instance = this;
    }

    public static BurpExtender getInstance() {
        return instance;
    }

    @Override
    public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
        // create a new instance of our custom editor tab
        return new JsonSchemaTab(controller, callbacks);
    }

    public JsonParserTab getParserTab() {
        return parserTab;
    }

    public IBurpExtenderCallbacks getCallbacks() {
        return callbacks;
    }
    
}
