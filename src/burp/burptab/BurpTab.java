
package burp.burptab;

import burp.ITab;
import java.awt.Component;
/**
 *
 * @author Joaquin R. Martinez
 */
public class BurpTab implements ITab, Cloneable{

    private Component contentComponent;
    private String tabString;
    
    public BurpTab(String tabstring, Component ui) {
        this.contentComponent = ui;
        this.tabString = tabstring;
    }

    public BurpTab() {
        this.contentComponent = null;
        this.tabString = "";
    }    

    @Override
    public String getTabCaption() {
        return this.tabString;
    }

    @Override
    public Component getUiComponent() {
        return this.contentComponent;
    }    

}
