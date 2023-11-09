# acme4j-no-common-name

This is an example of using the acme4j-client with a custom CSR which has no subject and thus no Common Name.

The provided acme4j CSRBuilder doesn't work because it always sets a CommonName.

This repo is a derivative work of acme4j and licensed under the same Apache 2 license.
