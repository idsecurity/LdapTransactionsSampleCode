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
package se.idsecurity.jldap.edirectoryjldapext.sample;

import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPException;
import java.security.GeneralSecurityException;
import com.novell.ldap.LDAPConstraints;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPSearchResults;
import se.idsecurity.jldap.edirectoryjldapext.controls.ExtendedDnControl;

/**
 * Simple example describing how to use LDAP the extended LDAP DN control.
 * Minimum error handling.
 *
 * @author almu
 */
public class SampleExtendedDnControl {

   
    /**
     * Pass the IP/DNS name of the LDAP server as the first argument,
     * Bind DN as the second argument and the password as third
     * argument.
     *
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        try {
            SampleExtendedDnControl et = new SampleExtendedDnControl(args);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public SampleExtendedDnControl(String[] args) throws GeneralSecurityException, LDAPException {

        String ldapServer = args[0];
        int port = 389;
        String bindDn = args[1];
        String password = args[2];

       
        LDAPConnection lc = new LDAPConnection();
        lc.connect(ldapServer, port);
        lc.bind(bindDn, password);

        //Use to get a DN such as this: <GUID=7467c7c083a8ca4848827467c7c083a8>;cn=adminadmin,o=System
        ExtendedDnControl guidAsHex = new ExtendedDnControl(ExtendedDnControl.GuidFormatFlag.HEX, true);
        
        //Use to get a DN such as this: <GUID=c0c76774-a883-48ca-4882-7467c7c083a8>;cn=adminadmin,o=System
        ExtendedDnControl guidAsString = new ExtendedDnControl(ExtendedDnControl.GuidFormatFlag.STRING, true);
        
        LDAPConstraints constraints = lc.getConstraints();
        
        constraints.setControls(guidAsHex);
        
        lc.setConstraints(constraints);
        
        LDAPSearchResults getGuidAsHex = lc.search(bindDn, LDAPConnection.SCOPE_BASE, "(objectClass=*)", null, false);
        
        if (getGuidAsHex.hasMore()) {
            LDAPEntry next = getGuidAsHex.next();
            System.out.println("DN with GUID in HEX format:");
            System.out.println(next.getDN());
        }
        
        constraints.setControls(guidAsString);
        
        lc.setConstraints(constraints);
        
        LDAPSearchResults getGuidAsString = lc.search(bindDn, LDAPConnection.SCOPE_BASE, "(objectClass=*)", null, false);
        
        if (getGuidAsString.hasMore()) {
            LDAPEntry next = getGuidAsString.next();
            System.out.println("DN with GUID in STRING format:");
            System.out.println(next.getDN());
        }
        
        lc.disconnect();
        

    }

}
