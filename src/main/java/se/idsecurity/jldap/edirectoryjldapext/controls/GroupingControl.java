/**
 * MIT License

Copyright (c) [2018] [almu]

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
 * GroupingControl ( 2.16.840.1.113719.1.27.103.7 ) - This is used to indicate
 * association of an operation to a grouping via the groupCookie which is the
 * value carried by this control.
 *
 * @see
 * <a href="https://www.netiq.com/documentation/edirectory-9/edir_admin/data/b4r36pg.html">Documentation</a>
 *
 */
public final class GroupingControl extends LDAPControl {

    private final LBEREncoder encoder = new LBEREncoder();

    private final ByteArrayOutputStream encodedData = new ByteArrayOutputStream();

    private final ASN1Sequence groupingControlValue = new ASN1Sequence();

    /**
     * Creates a new GroupingControl using the cookie received in a
     * CreateGroupingResponse in response to CreateGroupingRequest
     *
     * @param groupCookie The cookie from the CreateGroupingResponse
     * @param critial True if the LDAP operation should be discarded if the
     * control is not supported. False if the operation can be processed without
     * the control.
     */
    public GroupingControl(ASN1Integer groupCookie, boolean critial) {
        super(OID.GroupingControl.getOID(), critial, null);

        groupingControlValue.add(groupCookie);

        try {
            groupingControlValue.encode(encoder, encodedData);
            setValue(encodedData.toByteArray());
        } catch (IOException e) {
            //Shouldn't occur unless there is a serious failure
            throw new AssertionError("Unable to create instance of GroupingControl", e);
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

}
