
package burp.tab;

import java.awt.BorderLayout;
import java.awt.FlowLayout;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JSplitPane;
import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IMessageEditor;
import burp.ITextEditor;
import burp.pocs.Pocs;
import burp.tab.buttons.CopyPOCButton;
import burp.tab.buttons.SavePOCButton;

/**
 * POC Creator tab
 * 
 * @author Joaquin R. Martinez <joaquin.ramirez.mtz.lab@gmail.com>
 */
public class PocCreatorTab extends JPanel {

	private static final long serialVersionUID = 1L;
	private final ITextEditor textEditor;
	private IMessageEditor messageEditor;
	private POCTypesComboBox pocTypesCombo;

	/**
	 * Creates pocString new tab for pocString poc
	 *
	 * @param request the request to show on the left
	 * @param poc     the poc code
	 */
	public PocCreatorTab(IBurpExtenderCallbacks callbacks, IHttpRequestResponse request, Pocs pocs, byte[] poc) {
		super(new BorderLayout(10, 10));
		this.textEditor = callbacks.createTextEditor();
		this.pocTypesCombo = new POCTypesComboBox(textEditor, request, pocs);

		/* Making our message editor great with burp normal popup menu */
		MessageEditorController editorController = new MessageEditorController(callbacks.getHelpers(), request, messageEditor);
		this.messageEditor = callbacks.createMessageEditor(editorController, true);
		
		this.add(BorderLayout.CENTER, createEditorSplitPane());
		this.add(BorderLayout.SOUTH, createButtonsPanel(callbacks.getHelpers()));
		this.textEditor.setText(poc);
		this.messageEditor.setMessage(request.getRequest(), true);
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
		buttonsPanel.add(new CopyPOCButton(textEditor,helpers));
		buttonsPanel.add(new SavePOCButton(textEditor,helpers));
		return buttonsPanel;
	}

}
