/**
 * MIT License

Copyright (c) [2019] [almu]

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
 */
package se.idsecurity.jldap.edirectoryjldapext.controls;

import com.novell.ldap.LDAPControl;
import com.novell.ldap.asn1.ASN1Integer;
import com.novell.ldap.asn1.ASN1Sequence;
import com.novell.ldap.asn1.LBEREncoder;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import se.idsecurity.jldap.edirectoryjldapext.common.OID;

/**
 * LDAP_SERVER_EXTENDED_DN_OID  ( 1.2.840.113556.1.4.529 ) - This causes an 
 * LDAP server to return an extended form of the objects DN: <GUID=guid_value>;dn.
 *
 * @see
 * <a href="https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/57056773-932c-4e55-9491-e13f49ba580c">Documentation</a>
 *
 */
public final class ExtendedDnControl extends LDAPControl {

    private final LBEREncoder encoder = new LBEREncoder();

    private final ByteArrayOutputStream encodedData = new ByteArrayOutputStream();

    private final ASN1Sequence controlValue = new ASN1Sequence();

    /**
     * Creates a new ExtendedDnControl using the specified flag.
     *
     * @param flag The format of the GUID that will be returned.
     * @param critial True if the LDAP operation should be discarded if the
     * control is not supported. False if the operation can be processed without
     * the control.
     */
    public ExtendedDnControl(GuidFormatFlag flag, boolean critial) {
        super(OID.ExtendedDNControl.getOID(), critial, null);

        
        controlValue.add(new ASN1Integer(flag.getFlag()));

        try {
            controlValue.encode(encoder, encodedData);
            setValue(encodedData.toByteArray());
        } catch (IOException e) {
            //Shouldn't occur unless there is a serious failure
            throw new AssertionError("Unable to create instance of ExtendedDnControl", e);
        }

    }

    /**
     * Get the control as a byte array
     *
     * @return The control with the group cookie as encoded byte array
     */
    public byte[] getEncoded() {
        return encodedData.toByteArray();
    }
    
    /**
     * How will the LDAP server return the GUID value, 0 = HEX format, 1 = dashed string format.
     */
    public enum GuidFormatFlag {
        
        HEX(0),
        STRING(1);
       
        private final int flag;

        GuidFormatFlag(int flag) {
            this.flag = flag;
        }
               
        int getFlag() {
            return flag;
        }
        
    }

}
