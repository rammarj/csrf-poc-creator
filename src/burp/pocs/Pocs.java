
package burp.pocs;

import burp.pocs.types.AjaxPoc;
import java.util.Dictionary;
import java.util.Hashtable;

/**
 *
 * @author KMF
 */
public class Pocs {
    
    private static Dictionary<String, Poc> pocs = new Hashtable<String, Poc>() ;        

    public Pocs() {
        Pocs.pocs.put("Ajax",new AjaxPoc());
        
    }            

    public Poc getPoc(String key) {
        return Pocs.pocs.get(key);
    }        
    
}
