
package burp.util;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import burp.IParameter;

/**
 * Implementation of IParameter interface.
 *
 * @author Joaquin R. Martinez <joaquin.ramirez.mtz.lab@gmail.com>
 */
public class Parameter implements IParameter {

    private String name;
    protected String value;
    protected byte type;

    /**
     * Types of parameters.
     */
    public static final byte PARAM_HEADER = 20;
    public static final byte PARAM_MULTIPART = 21;
    public static final byte PARAM_FORM_URL_ENCODED = 22;
    public static final byte PARAM_UNKNOWN = 23;
    

    /**
     * Constructs a new parameter with its given name, value and type.
     * @param name the name of the parameter.
     * @param value the value of the parameter.
     * @param type the type of the parameter.
     */
    public Parameter(String name, String value, byte type) {
        this.name = name.trim();
        this.value = value.trim();
        this.type = type;
    }

    /**
     * Constructs a new parameter with empty name, value and PARAM_URL as its type.
     */
    public Parameter() {
        this("", "", PARAM_URL);
    }

    /** Sets the name of this parameter.
     * @param name the name of the parameter.
     */
    public void setName(String name) {
        this.name = name;
    }

    /**
     * Sets the value of this parameter.
     * @param value the value of thos parameter.
     */
    public void setValue(String value) {
        this.value = value;
    }
    
    /**
     * Deprecated
     * Deprecated. Use {@link #getParameterType() } instead.
     * @see #getParameterType()
     */
    @Override
    public byte getType() {
        return this.type;
    }
   
    /** Gets the name of this parameter.
     * @return the name of the parameter.
     */
    @Override
    public String getName() {
        return this.name;
    }

    /**
     * Gets the value of this parameter.
     * @return the value of this parameter.
     */
    @Override
    public String getValue() {
        return this.value;
    }

    /**
     * Gets the index where the name stars.
     * @return the index where the name starts.
     */
    @Override
    public int getNameStart() {
        return toString().indexOf(this.name);
    }

    /**
     * Gets the index where the name ends.
     * @return the index where the name ends.
     */
    @Override
    public int getNameEnd() {
        return getNameStart() + this.name.length();
    }

    /**
     * Gets the index where the value starts.
     * @return index where the value starts.
     */
    @Override
    public int getValueStart() {
        return toString().indexOf(this.getValue());
    }

    /**
     * Gets the index where the value ends.
     * @return the index where the value ends.
     */
    @Override
    public int getValueEnd() {
        return getValueStart() + this.value.length();
    }

    /**
     * Gets a string representation of this parameter.
     */
    @Override
    public String toString() {
        StringBuilder a = new StringBuilder();
        switch (type) {
            case PARAM_MULTIPART:
                a.append("Content-Disposition: form-data; name=\"")
                        .append(this.getName()).append("\"\r\n")
                        .append("\r\n").append(getValue()).append("\r\n");
                break;
            case PARAM_FORM_URL_ENCODED:
            case PARAM_URL:
				a.append(getName()).append("=").append(URLEncoder.encode(getValue(), StandardCharsets.UTF_8));
                break;
            case PARAM_HEADER:
                a.append(getName()).append(": ").append(getValue());
                break;
            default:
                a.append(getName()).append("=").append(getValue()).toString();
                break;
        }
        return a.toString();
    }
 
}
