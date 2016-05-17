
package burp;

import java.awt.Color;
import java.awt.Component;
import java.awt.Graphics;
import javax.swing.Icon;
/**
 * Creates the tab close icon
 * @author Joaquin R. Martinez
 */
public class CloseIcon implements Icon {
    
    @Override
    public void paintIcon(Component c, Graphics g, int x, int y) {
        g.setColor(Color.RED);
        g.drawLine(6, 6, getIconWidth() - 7, getIconHeight() - 7);
        g.drawLine(getIconWidth() - 7, 6, 6, getIconHeight() - 7);
    }

    @Override
    public int getIconWidth() {
        return 17;
    }

    @Override
    public int getIconHeight() {
        return 17;
    }

}
