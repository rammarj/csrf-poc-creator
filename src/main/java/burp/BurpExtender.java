package burp;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import burp.pocs.PocGenerator;
import burp.pocs.Pocs;
import burp.tab.PocCreatorTab;
import burp.tab.PocTabManager;
import burp.util.Request;

/**
 * CSRF POC Creator extension for Burp Suite
 * 
 * @author Joaquin R. Martinez <joaquin.ramirez.mtz.lab@gmail.com>
 */
public class BurpExtender implements IBurpExtender, IContextMenuFactory, ActionListener {

	private IBurpExtenderCallbacks burpExtenderCallbacks;
	private PocTabManager pocTabManager;
	private IContextMenuInvocation icMenuInvocation;
	private int tabCount;
	private Pocs pocs;
	private List<JMenuItem> menuItems;

	/** Initialize all variables needed */
	public BurpExtender() {
		this.tabCount = 1;
		this.menuItems = new ArrayList<>();
	}

	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks ibec) {
		this.burpExtenderCallbacks = ibec;
		this.pocTabManager = new PocTabManager();
		this.pocs = new Pocs();
		ibec.registerContextMenuFactory(this);
		ibec.setExtensionName("CSRF PoC Creator");
		this.burpExtenderCallbacks.addSuiteTab(this.pocTabManager);
		// add menus
		String[] pocKeys = this.pocs.getPocKeys();
		for (String key: pocKeys) {
			JMenuItem item = new JMenuItem(key);
			item.addActionListener(this);
			this.menuItems.add(item);
		}
	}

	/**
	 * Creates the menu items shown in burp suite
	 * 
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

	/**
	 * This method is executed when the "send to csrf ..." was clicked
	 * 
	 * @param e event argument
	 */
	@Override
	public void actionPerformed(ActionEvent e) {
		IHttpRequestResponse[] selectedMessages = this.icMenuInvocation.getSelectedMessages();
		for (IHttpRequestResponse ihrr : selectedMessages) {
			String selectedPOC = e.getActionCommand();
			PocGenerator pg = this.pocs.getPoc(selectedPOC);
			Request r = Request.fromHTTPRequestResponse(ihrr, this.burpExtenderCallbacks.getHelpers());
			byte[] poc = pg.generate(r);
			PocCreatorTab pct = new PocCreatorTab(this.burpExtenderCallbacks, ihrr, this.pocs, poc);
			pct.setSelectedItem(selectedPOC);
			this.pocTabManager.addTab(String.valueOf(this.tabCount++), pct);
		}
	}

}
