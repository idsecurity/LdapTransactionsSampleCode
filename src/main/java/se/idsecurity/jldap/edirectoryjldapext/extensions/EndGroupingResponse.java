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

import com.novell.ldap.LDAPExtendedResponse;
import com.novell.ldap.rfc2251.RfcLDAPMessage;

/**
 * EndGroupingResponse ( 2.16.840.1.113719.1.27.103.2 ) – This is the response
 * of the LDAP server to the endGroupingResponse indicating either success or
 * otherwise to the LDAP client.
 *
 * @see
 * <a href="https://www.netiq.com/documentation/edirectory-9/edir_admin/data/b4r36pg.html">Documentation</a>
 *
 */
public final class EndGroupingResponse extends LDAPExtendedResponse {

    public EndGroupingResponse(RfcLDAPMessage rfcMessage) {
        super(rfcMessage);

    }

}
