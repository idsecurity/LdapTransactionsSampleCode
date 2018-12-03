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
package se.idsecurity.jldap.edirectoryjldapext.extensions;

import se.idsecurity.jldap.edirectoryjldapext.controls.GroupingControl;
import com.novell.ldap.LDAPExtendedResponse;
import com.novell.ldap.asn1.ASN1Integer;
import com.novell.ldap.asn1.ASN1Object;
import com.novell.ldap.asn1.ASN1Sequence;
import com.novell.ldap.asn1.LBERDecoder;
import com.novell.ldap.rfc2251.RfcLDAPMessage;

/**
 * CreateGroupingResponse ( 2.16.840.1.113719.1.27.103.1 ) – This is the
 * response of the LDAP server to the createGroupingRequest and contains 2
 * response fields – groupCookie and an optional createGroupValue.
 *
 * @see
 * <a href="https://www.netiq.com/documentation/edirectory-9/edir_admin/data/b4r36pg.html">Documentation</a>
 *
 */
public final class CreateGroupingResponse extends LDAPExtendedResponse {

    private final ASN1Integer groupCookie;

    /**
     * Creates an response containing the GroupingControl needed for performing
     * LDAP operations
     *
     * @param rfcMessage
     */
    public CreateGroupingResponse(RfcLDAPMessage rfcMessage) {
        super(rfcMessage);

        byte[] value = getValue();
        LBERDecoder dec = new LBERDecoder();
        ASN1Sequence decode = (ASN1Sequence) dec.decode(value);
        ASN1Object first = decode.get(0);
        groupCookie = (ASN1Integer) first;

    }

    /**
     * Get the group cookie
     *
     * @return The group cookie
     */
    public ASN1Integer getGroupCookie() {
        return groupCookie;
    }

    /**
     * Get the GroupingControl for use with the LDAPConstraints object
     *
     * @param critical True if the LDAP operation should be discarded if the
     * control is not supported. False if the operation can be processed without
     * the control.
     * @return The GroupingControl containing the group cookie needed for
     * transactions.
     */
    public GroupingControl getControl(boolean critical) {
        GroupingControl gc = new GroupingControl(groupCookie, critical);
        return gc;
    }

}
