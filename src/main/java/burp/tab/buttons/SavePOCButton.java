package burp.tab.buttons;

import java.awt.Color;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;

import burp.BurpExtender;
import burp.ITextEditor;

public class SavePOCButton extends JButton implements ActionListener {

	private static final long serialVersionUID = 1L;
	private static final JFileChooser saveFileDialog = new JFileChooser();;
	private ITextEditor textEditor;

	public SavePOCButton(ITextEditor textEditor) {
		super("save to file");
		this.textEditor = textEditor;
		setForeground(Color.blue);
		addActionListener(this);
	}

	@Override
	public void actionPerformed(ActionEvent e) {
		int showSaveDialog = saveFileDialog.showSaveDialog(this.textEditor.getComponent());
		if (showSaveDialog == JFileChooser.APPROVE_OPTION) {
			File file = saveFileDialog.getSelectedFile();
			writeFileContents(file, this.textEditor.getText());
		}
	}

	private void writeFileContents(File file, byte[] text) {
		try (FileWriter fileWriter = new FileWriter(file);
				BufferedWriter bufferedWriter = new BufferedWriter(fileWriter)) {
			bufferedWriter.write(BurpExtender.getBurpExtenderCallbacks().getHelpers().bytesToString(text));
		} catch (IOException ex) {
			JOptionPane.showMessageDialog(this, ex, "Error", JOptionPane.ERROR_MESSAGE);
		}

	}

}
