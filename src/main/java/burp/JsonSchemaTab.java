package burp;

import java.awt.Component;

/**
 *
 * @author augustd
 */
public class JsonSchemaTab implements IMessageEditorTab {

    private ITextEditor txtInput;
    private byte[] currentMessage;

    public JsonSchemaTab(IMessageEditorController controller, IBurpExtenderCallbacks callbacks) {
        // create an instance of Burp's text editor, to display our deserialized data
        txtInput = callbacks.createTextEditor();
        txtInput.setEditable(false);
    }

    @Override
    public String getTabCaption() {
        return "JSON";
    }

    @Override
    public Component getUiComponent() {
        return txtInput.getComponent();
    }

    @Override
    public boolean isEnabled(byte[] content, boolean isRequest) {
        BurpExtender extender = BurpExtender.getInstance();

        return isRequest && extender.getParserTab().isJsonMessage(content);
    }

    @Override
    public void setMessage(byte[] content, boolean isRequest) {
        //save the message
        currentMessage = content;

        //set the JSON definition into the text area
        BurpExtender extender = BurpExtender.getInstance();
        String json = extender.getParserTab().getJsonString(content);

        txtInput.setText(json.getBytes());
    }

    @Override
    public byte[] getMessage() {
        return currentMessage;
    }

    @Override
    public boolean isModified() {
        return txtInput.isTextModified();
    }

    @Override
    public byte[] getSelectedData() {
        return txtInput.getSelectedText();
    }

}
