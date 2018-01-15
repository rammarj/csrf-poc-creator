
package burp.burptab;

import java.awt.Dimension;
import java.awt.event.ActionEvent;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;

/**
 * Creates the CSRF POC CREATOR tab
 * @author Joaquin R. Martinez <joaquin.ramirez.mtz.lab@gmail.com>
 */

public class PocTabManager extends JTabbedPane {

    /**
     * Ads pocString new tab within this tab with all requestInfo about the poc
     * @param title the title of the tab
     * @param pocCreatorTab the tab 
     */
    public void addTab(final String title, final PocCreatorTab pocCreatorTab) {        
        super.addTab(title, pocCreatorTab);
        int index = getTabCount() - 1;
        JPanel tabContainer = new JPanel();
        tabContainer.setOpaque(false);
        tabContainer.add(new JLabel(title));
        CloseIcon closeIcon = new CloseIcon();
        JButton closeTabButton = new JButton(closeIcon);
        closeTabButton.setPreferredSize(new Dimension(closeIcon.getIconWidth(), closeIcon.getIconHeight()));
        closeTabButton.addActionListener((ActionEvent e) -> {
            int indexOfTab = indexOfTab(title); //tabs title does not change
            if (indexOfTab != -1) {
                removeTabAt(indexOfTab);
            }
        });
        tabContainer.add(closeTabButton);
        setTabComponentAt(index, tabContainer);
    }
}
