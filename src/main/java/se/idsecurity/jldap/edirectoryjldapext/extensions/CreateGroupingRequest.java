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

import com.novell.ldap.LDAPExtendedOperation;
import com.novell.ldap.LDAPExtendedResponse;
import com.novell.ldap.asn1.ASN1OctetString;
import com.novell.ldap.asn1.ASN1Sequence;
import com.novell.ldap.asn1.LBEREncoder;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import se.idsecurity.jldap.edirectoryjldapext.common.OID;

/**
 * CreateGroupingRequest ( 2.16.840.1.113719.1.27.103.1 ) – This is LDAP
 * extended operation which allows grouping of related operations. The extended
 * operation carries a value – createGroupType which identifies the type of
 * grouping requested. For LDAP transactions, the grouping type is
 * transactionGroupingType. ( 2.16.840.1.113719.1.27.103.7)
 *
 * @see
 * <a href="https://www.netiq.com/documentation/edirectory-9/edir_admin/data/b4r36pg.html">Documentation</a>
 *
 */
public final class CreateGroupingRequest extends LDAPExtendedOperation {

    private final ByteArrayOutputStream encodedData = new ByteArrayOutputStream();
    private final LBEREncoder encoder = new LBEREncoder();
    private final ASN1OctetString createGroupType = new ASN1OctetString(OID.GroupingControl.getOID());
    private final ASN1Sequence sequence = new ASN1Sequence(1);

    /**
     * Creates an extended operations object for retrieving a group cookie for
     * use with the LDAP transactions GroupingControl
     */
    public CreateGroupingRequest() {
        super(OID.CreateGroupingRequest.getOID(), null);

        LDAPExtendedResponse.register(OID.CreateGroupingResponse.getOID(), CreateGroupingResponse.class);

        try {
            sequence.add(createGroupType);
            sequence.encode(encoder, encodedData);
        } catch (IOException e) {
            //Shouldn't occur unless there is a serious failure
            throw new AssertionError("Could not create instance of CreateGroupingRequest", e);
        }
        setValue(encodedData.toByteArray());
    }
}
