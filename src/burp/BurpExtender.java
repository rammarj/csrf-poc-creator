package burp;

import burp.burptab.BurpTab;
import burp.burptab.PocCreatorTab;
import burp.burptab.PocTabManager;
import burp.pocs.Poc;
import burp.pocs.Pocs;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.LinkedList;
import java.util.List;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;

/**
 * CSRF POC Creator extension for Burp Suite
 * @author Joaquin R. Martinez <joaquin.ramirez.mtz.lab@gmail.com>
 */
public class BurpExtender implements IBurpExtender, IContextMenuFactory, ActionListener {

    private IBurpExtenderCallbacks iexCallbacks;
    private PocTabManager pocTabManager;
    private IContextMenuInvocation icMenuInvocation;
    private final JMenuItem sendMenuItem;
    private int tabCount;
    private final LinkedList<JMenuItem> menuItems;
    private Pocs pocs;
    /**Initialize all variables needed*/
    public BurpExtender() {
        this.menuItems = new LinkedList<>();
        this.sendMenuItem = new JMenuItem("send to CSRF PoC Creator");
        this.sendMenuItem.addActionListener(BurpExtender.this);
        menuItems.add(this.sendMenuItem);
        this.tabCount = 1;        
    }
    
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks ibec) {
        this.iexCallbacks = ibec;
        this.pocTabManager = new PocTabManager();
        ibec.registerContextMenuFactory(this);
        ibec.setExtensionName("CSRF PoC Creator");
        this.iexCallbacks.addSuiteTab(new BurpTab("CSRF PoC", this.pocTabManager));
        this.pocs = new Pocs();
    }
    
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
                Poc poc = this.pocs.getPoc("Ajax");
                byte[] pocContent = poc.getPoc(iexCallbacks.getHelpers(), ihrr);
                PocCreatorTab pocCreatorTab = new PocCreatorTab(iexCallbacks, ihrr, pocContent);
                this.pocTabManager.addTab(String.valueOf((this.tabCount++)), pocCreatorTab);
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this.pocTabManager, ex.getMessage());
            }
        }
    }
}
