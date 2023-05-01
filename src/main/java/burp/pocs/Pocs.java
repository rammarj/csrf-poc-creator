
package burp.pocs;

import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

/**
 * Contains all types of PoC's supported by this plugin.
 * 
 * @author Joaquin R. Martinez <joaquin.ramirez.mtz.lab@gmail.com>
 */
public class Pocs {

	private final Map<String, PocGenerator> pocs;

	/**
	 * Inaccesible constructor.
	 */
	public Pocs() {
		this.pocs = new HashMap<>();
		this.pocs.put("Ajax", new AjaxPocGenerator());
		this.pocs.put("HTML", new HtmlPocGenerator());
		// Add more kind of PoC's
	}

	/**
	 * Get the {@link PocGenerator} object by its key.
	 * 
	 * @param key the key of the {@link PocGenerator}.
	 * @return the {@link PocGenerator} object.
	 */
	public PocGenerator getPoc(String key) {
		return pocs.get(key);
	}

	/**
	 * Get the {@link PocGenerator} as an array.
	 * 
	 * @return an array of keys.
	 */
	public String[] getPocKeys() {
		return this.pocs.keySet().toArray(new String[] {});
	}

}
