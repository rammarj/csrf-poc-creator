
package burp.tab;

import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.util.Iterator;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JSplitPane;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IMessageEditor;
import burp.ITextEditor;
import burp.pocs.PocGenerator;
import burp.pocs.Pocs;
import burp.tab.buttons.CopyPOCButton;
import burp.tab.buttons.SavePOCButton;
import burp.util.MessageEditorController;
import burp.util.Request;

/**
 * POC Creator tab
 * 
 * @author Joaquin R. Martinez <joaquin.ramirez.mtz.lab@gmail.com>
 */
public class PocCreatorTab extends JPanel {

	private static final long serialVersionUID = 1L;
	private final ITextEditor textEditor;
	private IMessageEditor messageEditor;
	private JComboBox<String> pocTypesCombo;

	/**
	 * Creates pocString new tab for pocString poc
	 *
	 * @param ihrr       the request to show on the left
	 * @param currentPoc the poc code
	 */
	public PocCreatorTab(IBurpExtenderCallbacks callbacks, IHttpRequestResponse ihrr, Pocs pocs, byte[] currentPoc) {
		super(new BorderLayout(10, 10));
		this.textEditor = callbacks.createTextEditor();
		IExtensionHelpers helpers = callbacks.getHelpers();

		/* Making our message editor great with burp normal popup menu */
		MessageEditorController editorController = new MessageEditorController(helpers, ihrr, messageEditor);
		this.messageEditor = callbacks.createMessageEditor(editorController, true);
		// POC types combo
		this.pocTypesCombo = new JComboBox<>();
		Iterator<String> pocKeys = pocs.getPocKeys();
		while (pocKeys.hasNext()) {
			pocTypesCombo.addItem(pocKeys.next());
		}

		pocTypesCombo.addItemListener(e -> {
			String selectedItem = pocTypesCombo.getSelectedItem().toString();
			PocGenerator generator = pocs.getPoc(selectedItem);
			if (this.messageEditor.isMessageModified())
				ihrr.setRequest(this.messageEditor.getMessage());

			byte[] pocContent = null;
			try {
				pocContent = generator.generate(Request.fromHTTPRequestResponse(ihrr, helpers));
			} catch (Exception ex) {
				JOptionPane.showMessageDialog(this, ex.getMessage(), "", JOptionPane.WARNING_MESSAGE);
			}
			this.textEditor.setText(pocContent);
		});

		this.add(BorderLayout.CENTER, createEditorSplitPane());
		this.add(BorderLayout.SOUTH, createButtonsPanel(helpers));
		this.textEditor.setText(currentPoc);
		this.messageEditor.setMessage(ihrr.getRequest(), true);
		callbacks.customizeUiComponent(PocCreatorTab.this);// burp lookandfeel
	}

	/**
	 * Sets the selected poc item.
	 * 
	 * @param key the item.
	 */
	public void setSelectedItem(String key) {
		this.pocTypesCombo.setSelectedItem(key);
	}

	private JSplitPane createEditorSplitPane() {
		JSplitPane editorArea = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
		editorArea.add(this.messageEditor.getComponent());
		editorArea.add(this.textEditor.getComponent());
		return editorArea;
	}

	private JPanel createButtonsPanel(IExtensionHelpers helpers) {
		JPanel buttonsPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
		buttonsPanel.add(new JLabel("PoC type: "));
		buttonsPanel.add(pocTypesCombo);
		buttonsPanel.add(new CopyPOCButton(textEditor, helpers));
		buttonsPanel.add(new SavePOCButton(textEditor, helpers));
		return buttonsPanel;
	}

}
