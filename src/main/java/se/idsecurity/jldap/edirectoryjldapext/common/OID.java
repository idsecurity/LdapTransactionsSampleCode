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
package se.idsecurity.jldap.edirectoryjldapext.common;

/**
 * OID's used for LDAP transactions
 */
public enum OID {

    CreateGroupingRequest("2.16.840.1.113719.1.27.103.1"),
    CreateGroupingResponse("2.16.840.1.113719.1.27.103.1"),
    EndGroupingRequest("2.16.840.1.113719.1.27.103.2"),
    EndGroupingResponse("2.16.840.1.113719.1.27.103.2"),
    GroupingControl("2.16.840.1.113719.1.27.103.7");

    private final String oid;

    OID(String oid) {
        this.oid = oid;
    }

    /**
     * Get the OID for the LDAP extension/control
     *
     * @return
     */
    public String getOID() {
        return oid;
    }

}
