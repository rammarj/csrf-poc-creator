
package burp.burptab;

import burp.BurpExtender;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IHttpServiceImpl;
import burp.IMessageEditor;
import burp.IMessageEditorController;
import burp.IRequestInfo;
import burp.ITextEditor;
import burp.pocs.Poc;
import burp.pocs.Pocs;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.FlowLayout;
import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Enumeration;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JSplitPane;

/**
 * POC Creator tab
 * @author Joaquin R. Martinez <joaquin.ramirez.mtz.lab@gmail.com>
 */
public class PocCreatorTab extends JPanel implements ActionListener, ItemListener {

    private final ITextEditor textEditor;
    private final IMessageEditor messageEditor;
    private final JButton saveButton, copyButton;//, btn_close;
    private final JFileChooser saveFileDialog;
    private final JComboBox<String> pocTypesCombo;
    private final IHttpRequestResponse request;
    
    /**
     * Creates pocString new tab for pocString poc
     *
     * @param iexCallbacks object to use
     * @param req the request to show on the left
     * @param poc the poc code
     */
    public PocCreatorTab(IHttpRequestResponse req, byte[] poc) {
        super(new BorderLayout(10, 10));
        this.request = req;
        this.saveButton = new JButton("save to file");
        this.copyButton = new JButton("copy");
        this.saveButton.setForeground(Color.blue);
        this.copyButton.addActionListener(PocCreatorTab.this);
        this.saveButton.addActionListener(PocCreatorTab.this);
        this.saveFileDialog = new JFileChooser();
        this.pocTypesCombo = new JComboBox<>();
        Enumeration<String> pocKeys = Pocs.getPocKeys();
        while (pocKeys.hasMoreElements()) {
            String nextElement = pocKeys.nextElement();
            this.pocTypesCombo.addItem(nextElement);
        }
        this.pocTypesCombo.addItemListener(this);
        /*Create pocString TextEditor*/
        this.textEditor = BurpExtender.getBurpExtenderCallbacks().createTextEditor();
        /*Making our message editor great with burp normal popup menu*/
        this.messageEditor = BurpExtender.getBurpExtenderCallbacks().createMessageEditor(new IMessageEditorController() {
            @Override
            public IHttpService getHttpService() {
                IRequestInfo analyzeRequest = BurpExtender.getBurpExtenderCallbacks().getHelpers().analyzeRequest(req);
                return new IHttpServiceImpl(analyzeRequest);
            }

            @Override
            public byte[] getRequest() {
                return messageEditor.getMessage();
            }

            @Override
            public byte[] getResponse() {
                return req.getResponse();
            }
        }, true);        
        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        splitPane.add(this.messageEditor.getComponent());
        splitPane.add(this.textEditor.getComponent());
        PocCreatorTab.this.add("Center", splitPane);
        //buttons panel
        JPanel buttonsPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        buttonsPanel.add(new JLabel("PoC type: "));
        buttonsPanel.add(this.pocTypesCombo);
        buttonsPanel.add(this.copyButton);
        buttonsPanel.add(this.saveButton);
        //add buttons to end
        PocCreatorTab.this.add("South", buttonsPanel);
        this.textEditor.setText(poc);
        this.messageEditor.setMessage(req.getRequest(), true);
        BurpExtender.getBurpExtenderCallbacks().customizeUiComponent(PocCreatorTab.this);//burp lookandfeel
    }

    /**
     * When pocString button is clicked into this tab
     */
    @Override
    public void actionPerformed(ActionEvent e) {
        if (e.getSource() == this.copyButton) {
            copy();
        } else if (e.getSource() == this.saveButton) {
            save();
        }
    }

    /**
     * Passes the poc code to the system clipboard
     */
    private void copy() {
        IExtensionHelpers helpers = BurpExtender.getBurpExtenderCallbacks().getHelpers();
        String bytesToString = helpers.bytesToString(this.textEditor.getText());  
        Clipboard systemClipboard = Toolkit.getDefaultToolkit().getSystemClipboard();      
        systemClipboard.setContents(new StringSelection(bytesToString), null);
    }

    private void save() {
        int showSaveDialog = this.saveFileDialog.showSaveDialog(this.textEditor.getComponent());
        if (showSaveDialog == JFileChooser.APPROVE_OPTION) {
            try {
                File file = this.saveFileDialog.getSelectedFile();
                try (FileWriter fileWriter = new FileWriter(file);
                        BufferedWriter bufferedWriter = new BufferedWriter(fileWriter)) {
                    bufferedWriter.write(BurpExtender.getBurpExtenderCallbacks().getHelpers().bytesToString(this.textEditor.getText()));
                    bufferedWriter.flush();
                    fileWriter.flush();
                }
            } catch (IOException ex) {
                JOptionPane.showMessageDialog(this, ex, "Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    @Override
    public void itemStateChanged(ItemEvent e) {
        String selectedItem = this.pocTypesCombo.getSelectedItem().toString();
        Poc poc = Pocs.getPoc(selectedItem);
        try {
            byte[] pocContent = poc.getPoc(this.request);
            this.textEditor.setText(pocContent);
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, ex, "Error", JOptionPane.ERROR_MESSAGE);
        }        
    }

}
