
package burp.pocs;

import java.util.Dictionary;
import java.util.Enumeration;
import java.util.Hashtable;

/**
 *
 * @author Joaquin R. Martinez <joaquin.ramirez.mtz.lab@gmail.com>
 */
public class Pocs {
    
    private static Dictionary<String, Poc> pocs = new Hashtable<String, Poc>() ;        
    private static Pocs poc = null;
    
    private Pocs() {
        Pocs.pocs.put("Ajax",new AjaxPoc());    
        // Add more kind of PoC's
    }            

    public static void initialize(){
        if(poc == null){
            Pocs.poc = new Pocs();
        }
    }
    
    public static Poc getPoc(String key) {
        return Pocs.pocs.get(key);
    }        
    
    public static Enumeration<String> getPocKeys(){
        return Pocs.pocs.keys();
    }
    
}
