package org.apache.shiro.spring.boot.ldap.exception;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("LdapConnectionException Tests")
class LdapConnectionExceptionTest {

    @Test
    @DisplayName("Default constructor")
    void testDefaultConstructor() {
        LdapConnectionException ex = new LdapConnectionException();
        assertThat(ex).isNotNull();
        assertThat(ex).isInstanceOf(org.apache.shiro.authc.AuthenticationException.class);
    }

    @Test
    @DisplayName("Constructor with message and cause")
    void testMessageAndCause() {
        RuntimeException cause = new RuntimeException("root");
        LdapConnectionException ex = new LdapConnectionException("msg", cause);
        assertThat(ex.getMessage()).isEqualTo("msg");
        assertThat(ex.getCause()).isEqualTo(cause);
    }

    @Test
    @DisplayName("Constructor with message")
    void testMessage() {
        LdapConnectionException ex = new LdapConnectionException("error");
        assertThat(ex.getMessage()).isEqualTo("error");
    }

    @Test
    @DisplayName("Constructor with cause")
    void testCause() {
        RuntimeException cause = new RuntimeException("root");
        LdapConnectionException ex = new LdapConnectionException(cause);
        assertThat(ex.getCause()).isEqualTo(cause);
    }
}
