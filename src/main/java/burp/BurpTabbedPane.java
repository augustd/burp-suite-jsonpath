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
		//add the component that renders when the tab is selected
        Component output = super.add(name, component);
		//add the tab component: renders instead of the default tab name
        setTabComponentAt(indexOfComponent(component), new BurpTabComponent(name, this));
        return output;
    }
    
}
