package burp;

import burp.ui.JsonParserTab;
import com.codemagi.burp.BaseExtender;

/**
 * JSON Explorer: A BurpSuite extension to parse JSON responses and enable searching
 * for specific elements using JSON Path expression language
 *
 * @author augustd
 */
public class BurpExtender extends BaseExtender implements IBurpExtender {

    public static final String TAB_NAME = "JSON";
    public static final String EXTENSION_NAME = "JSON Explorer";
    private static BurpExtender instance;
    private JsonParserTab parserTab;

    @Override
    protected void initialize() {
        extensionName = EXTENSION_NAME;

        parserTab = new JsonParserTab(callbacks);
        callbacks.customizeUiComponent(parserTab);

        callbacks.registerContextMenuFactory(new Menu(callbacks, parserTab));

        instance = this;
    }

    public static BurpExtender getInstance() {
        return instance;
    }

    public JsonParserTab getParserTab() {
        return parserTab;
    }

}
