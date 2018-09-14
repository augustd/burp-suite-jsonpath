package burp;

import java.awt.Component;
import javax.swing.JTabbedPane;

/**
 *
 * @author august
 */
class BurpTabbedPane extends JTabbedPane {
    
    @Override
    public Component add(String name, Component component) {
        Component output = super.add(name, component);
        setTabComponentAt(indexOfComponent(component), new BurpTabComponent(name, this));
        return output;
    }
    
}
