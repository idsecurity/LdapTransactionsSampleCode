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
package se.idsecurity.jldap.edirectoryjldapext.sample;

import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPExtendedResponse;
import java.security.GeneralSecurityException;
import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPConstraints;
import com.novell.ldap.LDAPModification;
import java.time.Instant;
import se.idsecurity.jldap.edirectoryjldapext.controls.GroupingControl;
import se.idsecurity.jldap.edirectoryjldapext.extensions.CreateGroupingRequest;
import se.idsecurity.jldap.edirectoryjldapext.extensions.CreateGroupingResponse;
import se.idsecurity.jldap.edirectoryjldapext.extensions.EndGroupingRequest;
import se.idsecurity.jldap.edirectoryjldapext.extensions.EndGroupingResponse;

/**
 * Simple example describing how to use LDAP transactions with eDirectory.
 * Minimum error handling.
 *
 * @author almu
 */
public class SampleEdirTransaction {

    /**
     * The objects we are going to modify
     */
    private final String firstObjectToModify = "cn=labdi999305,ou=POC,dc=test";
    private final String secondObjectToModify = "cn=vabdi997915,ou=POC,dc=test";

    /**
     * Something to write to the description attribute
     */
    private final Instant currentTime = Instant.now();

    /**
     * Pass the Bind DN as the first argument and the password as second
     * argument
     *
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        try {
            SampleEdirTransaction et = new SampleEdirTransaction(args);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public SampleEdirTransaction(String[] args) throws GeneralSecurityException, LDAPException {

        String ldapServer = "192.168.0.6";
        int port = 389;
        String bindDn = args[0];
        String password = args[1];

        LDAPModification addTimeToDesc = new LDAPModification(LDAPModification.REPLACE, new LDAPAttribute("description", currentTime.toString()));
        LDAPModification delSn = new LDAPModification(LDAPModification.DELETE, new LDAPAttribute("sn"));
        LDAPModification[] mods = {addTimeToDesc, delSn};

        LDAPConnection lc = new LDAPConnection();
        lc.connect(ldapServer, port);
        lc.bind(bindDn, password);

        CreateGroupingRequest gr = new CreateGroupingRequest();

        LDAPExtendedResponse createGroupingRequest = lc.extendedOperation(gr);

        if (createGroupingRequest instanceof CreateGroupingResponse) {
            CreateGroupingResponse resp = (CreateGroupingResponse) createGroupingRequest;

            GroupingControl control = resp.getControl(true);

            LDAPConstraints constraints = lc.getConstraints();
            constraints.setControls(control);

            lc.modify(firstObjectToModify, addTimeToDesc, constraints);
            lc.modify(secondObjectToModify, delSn, constraints);

            LDAPExtendedResponse endGroupingResponse = lc.extendedOperation(new EndGroupingRequest(control));

            if (endGroupingResponse instanceof EndGroupingResponse) {
                System.out.println(endGroupingResponse);
            }

        }

    }

}
