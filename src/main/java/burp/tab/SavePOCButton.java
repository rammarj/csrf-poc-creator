package burp.tab;

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

public abstract class SavePOCButton extends JButton implements ActionListener {

	private static final long serialVersionUID = 1L;
	private static final JFileChooser saveFileDialog = new JFileChooser();

	public SavePOCButton() {
		super("save to file");
		setForeground(Color.blue);
		addActionListener(this);
	}

	@Override
	public void actionPerformed(ActionEvent e) {
		int showSaveDialog = saveFileDialog.showSaveDialog(this);
		if (showSaveDialog == JFileChooser.APPROVE_OPTION) {
			File file = saveFileDialog.getSelectedFile();
			writeFileContents(file, getTextToSave());
		}
	}
	
	public abstract String getTextToSave();

	private void writeFileContents(File file, String text) {
		try (FileWriter fileWriter = new FileWriter(file);
				BufferedWriter bufferedWriter = new BufferedWriter(fileWriter)) {
			bufferedWriter.write(text);
		} catch (IOException ex) {
			JOptionPane.showMessageDialog(this.getParent(), ex, "Error saving file", JOptionPane.ERROR_MESSAGE);
		}
	}

}
