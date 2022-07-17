package burp;

import burp.burptab.ITabImpl;
import burp.burptab.PocCreatorTab;
import burp.burptab.PocTabManager;
import burp.pocs.Pocs;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import burp.pocs.IPoc;

/**
 * CSRF POC Creator extension for Burp Suite
 * 
 * @author Joaquin R. Martinez <joaquin.ramirez.mtz.lab@gmail.com>
 */
public class BurpExtender implements IBurpExtender, IContextMenuFactory, ActionListener {

    private static IBurpExtenderCallbacks burpExtenderCallbacks;
    private PocTabManager pocTabManager;
    private IContextMenuInvocation icMenuInvocation;
    private int tabCount;
    private final LinkedList<JMenuItem> menuItems;
    
    /**Initialize all variables needed*/
    public BurpExtender() {
        this.menuItems = new LinkedList<>();
        this.tabCount = 1;        
    }
    
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks ibec) {
        BurpExtender.burpExtenderCallbacks = ibec;
        this.pocTabManager = new PocTabManager();
        ibec.registerContextMenuFactory(this);
        ibec.setExtensionName("CSRF PoC Creator");
        BurpExtender.burpExtenderCallbacks.addSuiteTab(new ITabImpl("CSRF PoC", this.pocTabManager));
        Pocs.initialize();
        // add menus
        Iterator<String> pocKeys = Pocs.getPocKeys();
        while (pocKeys.hasNext()) {
            String key = pocKeys.next();
            JMenuItem item = new JMenuItem(key);
            item.addActionListener(BurpExtender.this);
            this.menuItems.add(item);
        }
        BurpExtender.burpExtenderCallbacks.printOutput("Burp csrf-poc-creator plugin for Burp Suite Free loaded!");
        BurpExtender.burpExtenderCallbacks.printOutput("Created by @rammarj");
    }
    /**
     * Creates the menu items shown in burp suite
     * @param icmi the context menu invocation
     * @return List of menu items
     */
    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation icmi) {
        this.icMenuInvocation = icmi;
        byte invocation_context = icmi.getInvocationContext();
        if (invocation_context == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST
                || invocation_context == IContextMenuInvocation.CONTEXT_PROXY_HISTORY
                || invocation_context == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST) {
            return menuItems;
        }
        return null;
    }
    
    /**This method is executed when the "send to csrf ..." was clicked
     * @param e event argument
     */
    @Override
    public void actionPerformed(ActionEvent e) {
        IHttpRequestResponse[] selectedMessages = this.icMenuInvocation.getSelectedMessages();
        for (IHttpRequestResponse ihrr : selectedMessages) {
            try {
                String actionCommand = e.getActionCommand();
                IPoc poc = Pocs.getPoc(actionCommand);
                byte[] pocContent = poc.getPoc(ihrr);
                
                PocCreatorTab pocCreatorTab = new PocCreatorTab(ihrr, pocContent);
                pocCreatorTab.setSelectedItem(actionCommand);
                this.pocTabManager.addTab(String.valueOf((this.tabCount++)), pocCreatorTab);
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this.pocTabManager, ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }
    
    /**
     * Get the extender callback for this plugin
     * @return the extender callbacks
     */
    public static IBurpExtenderCallbacks getBurpExtenderCallbacks() {
        return burpExtenderCallbacks;
    }
        
}
