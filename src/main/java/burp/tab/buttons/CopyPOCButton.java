package burp.tab.buttons;

import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import javax.swing.JButton;
import burp.BurpExtender;
import burp.IExtensionHelpers;
import burp.ITextEditor;

public class CopyPOCButton extends JButton implements ActionListener{

	private static final long serialVersionUID = 1L;
	
	private ITextEditor textEditor;
	
	public CopyPOCButton(ITextEditor textEditor) {
		super("copy");
		this.textEditor = textEditor;
		addActionListener(this);
	}

	@Override
	public void actionPerformed(ActionEvent e) {
		IExtensionHelpers helpers = BurpExtender.getBurpExtenderCallbacks().getHelpers();
        String bytesToString = helpers.bytesToString(this.textEditor.getText());  
        Clipboard systemClipboard = Toolkit.getDefaultToolkit().getSystemClipboard();      
        systemClipboard.setContents(new StringSelection(bytesToString), null);
	}
	
}
