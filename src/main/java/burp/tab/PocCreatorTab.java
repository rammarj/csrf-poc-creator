package burp.tab;

import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JSplitPane;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IMessageEditor;
import burp.ITextEditor;
import burp.pocs.PocGenerator;
import burp.pocs.Pocs;
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
	private final JComboBox<String> pocTypesCombo = new JComboBox<>();

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
		String[] pocKeys = pocs.getPocKeys();
		for (String key : pocKeys) {
			pocTypesCombo.addItem(key);
		}

		pocTypesCombo.addItemListener(e -> {
			String selectedItem = pocTypesCombo.getSelectedItem().toString();
			PocGenerator generator = pocs.getPoc(selectedItem);
			ihrr.setRequest(this.messageEditor.getMessage());
			byte[] pocContent = generator.generate(Request.fromHTTPRequestResponse(ihrr, helpers));
			this.textEditor.setText(pocContent);
		});

		JSplitPane editors = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, this.messageEditor.getComponent(),
				this.textEditor.getComponent());
		this.add(BorderLayout.CENTER, editors);
		this.add(BorderLayout.SOUTH, createButtonsPanel(helpers));
		this.textEditor.setText(currentPoc);
		this.messageEditor.setMessage(ihrr.getRequest(), true);
		callbacks.customizeUiComponent(this);// burp lookandfeel
	}

	/**
	 * Sets the selected poc item.
	 * 
	 * @param key the item.
	 */
	public void setSelectedItem(String key) {
		this.pocTypesCombo.setSelectedItem(key);
	}

	private JPanel createButtonsPanel(IExtensionHelpers helpers) {
		JPanel buttonsPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
		JButton copyButton = new JButton("copy");
		copyButton.addActionListener(e -> {
			String text = helpers.bytesToString(this.textEditor.getText());
			Clipboard systemClipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
			systemClipboard.setContents(new StringSelection(text), null);
		});
		buttonsPanel.add(new JLabel("PoC type: "));
		buttonsPanel.add(pocTypesCombo);
		buttonsPanel.add(copyButton);
		buttonsPanel.add(new SavePOCButton() {
			private static final long serialVersionUID = 1L;

			@Override
			public String getTextToSave() {
				return helpers.bytesToString(textEditor.getText());
			}
		});
		return buttonsPanel;
	}

}
