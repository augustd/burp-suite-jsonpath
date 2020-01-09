package burp;

import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.FocusAdapter;
import java.awt.event.FocusEvent;
import java.awt.event.FocusListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;

import javax.swing.*;
import javax.swing.plaf.basic.BasicButtonUI;

/**
 * Component to be used as tabComponent: Renders instead of a default tab name.  
 * 
 * Contains a JLabel to show the (editable) tab name and a JButton to close the tab
 */
public class BurpTabComponent extends JPanel {

    private final JTabbedPane pane; //the pane of tabs that will contain this one
    private final JTextField editor = new JTextField();
    private static final Color TRANSPARENT = new Color(255, 255, 255, 0);

    public BurpTabComponent(String title, final JTabbedPane pane) {
        //unset default FlowLayout' gaps
        super(new FlowLayout(FlowLayout.LEFT, 0, 0));
        if (pane == null) {
            throw new NullPointerException("TabbedPane is null");
        }
        this.pane = pane;

        //create an editor component
        editor.setBorder(BorderFactory.createEmptyBorder(0, 3, 0, 7));
        editor.setText(title);
        editor.setBackground(TRANSPARENT);
        editor.setOpaque(false);
        editor.setEditable(false);
        BurpExtender.getCallbacks().customizeUiComponent(editor);
        add(editor);

        //Make editor not editable until double-click
        editor.setEditable(false);
        editor.setEnabled(false);
        editor.setDisabledTextColor(Color.BLACK);
        editor.addMouseListener(DOUBLE_CLICK_LISTENER);
        editor.addFocusListener(FOCUS_LOST_LISTENER);

        //Add the close button
        JButton button = new TabButton();
        add(button);

        //add more space to the top of the component
        setBorder(BorderFactory.createEmptyBorder(2, 0, 0, 0));
        setBackground(TRANSPARENT);
        setOpaque(false);
    }

    private class TabButton extends JButton implements ActionListener {

        public TabButton() {
            int size = 9;
            setPreferredSize(new Dimension(size, size));
            setToolTipText("close this tab");
            //Make the button looks the same for all Laf's
            setUI(new BasicButtonUI());
            //Make it transparent
            setContentAreaFilled(false);
            //No need to be focusable
            setFocusable(false);
            setBorder(BorderFactory.createLineBorder(Color.BLACK, 1));
            setBorderPainted(false);
            this.setMargin(new Insets(11, 6, 0, 0));

            //Making nice rollover effect
            //we use the same listener for all buttons
            addMouseListener(BUTTON_MOUSE_LISTENER);
            setRolloverEnabled(true);
            //Close the proper tab by clicking the button
            addActionListener(this);
            BurpExtender.getCallbacks().customizeUiComponent(this);
        }

        @Override
        public void actionPerformed(ActionEvent e) {
            int i = pane.indexOfTabComponent(BurpTabComponent.this);
            if (i != -1) {
                pane.remove(i);
            }
        }

        //we don't want to update UI for this button
        @Override
        public void updateUI() {
        }

        //paint the cross
        @Override
        protected void paintComponent(Graphics g) {
            super.paintComponent(g);
            Graphics2D g2 = (Graphics2D) g.create();
            //shift the image for pressed buttons
            if (getModel().isPressed()) {
                g2.translate(1, 1);
            }
            g2.setStroke(new BasicStroke(1));
            g2.setColor(Color.GRAY);
            if (getModel().isRollover()) {
                g2.setColor(Color.BLACK);
            }
            int delta = 6;
            g2.drawLine(2, 3, 6, 7);
            g2.drawLine(2, 7, 6, 3);
            g2.dispose();
        }
    }

	/**
	 * Create rollover effect for X button
	 */
    private final static MouseListener BUTTON_MOUSE_LISTENER = new MouseAdapter() {
        @Override
        public void mouseEntered(MouseEvent e) {
            Component component = e.getComponent();
            if (component instanceof AbstractButton) {
                AbstractButton button = (AbstractButton) component;
                button.setBorderPainted(true);
            }
        }

        @Override
        public void mouseExited(MouseEvent e) {
            Component component = e.getComponent();
            if (component instanceof AbstractButton) {
                AbstractButton button = (AbstractButton) component;
                button.setBorderPainted(false);
            }
        }
    };

    private final MouseListener DOUBLE_CLICK_LISTENER = new MouseAdapter() {
        @Override
        public void mouseClicked(MouseEvent e) {
            Component component = e.getComponent();
			component.requestFocusInWindow();
			if (e.getClickCount() >= 1) {
				System.out.println("single-click");
				pane.setSelectedIndex(pane.indexOfTabComponent(BurpTabComponent.this));
			}
            if (e.getClickCount() == 2) {
                System.out.println("double-click");
                JTextField field = (JTextField) component;
                field.setEditable(true);
                field.setEnabled(true);
            } 
        }
    };

	/**
	 * Make label field un-editable when it loses focus
	 */
    private static final FocusListener FOCUS_LOST_LISTENER = new FocusAdapter() {
        @Override
        public void focusLost(FocusEvent e) {
            Component component = e.getComponent();
            System.out.println("User exited");
            JTextField field = (JTextField) component;
            field.setEditable(false);
            field.setEnabled(false);
        }
    };

}
