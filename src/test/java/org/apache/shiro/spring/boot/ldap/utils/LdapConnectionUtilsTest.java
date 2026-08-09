package org.apache.shiro.spring.boot.ldap.utils;

import org.apache.directory.ldap.client.api.LdapConnection;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.apache.shiro.spring.boot.ldap.exception.LdapConnectionException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.MockedConstruction;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

@DisplayName("LdapConnectionUtils Tests")
class LdapConnectionUtilsTest {

    @Test
    @DisplayName("openConnection returns connection on success")
    void testOpenConnectionSuccess() throws Exception {
        try (MockedConstruction<LdapNetworkConnection> mocked = mockConstruction(LdapNetworkConnection.class,
                (mock, ctx) -> {
                    // bind succeeds
                })) {
            LdapConnection conn = LdapConnectionUtils.openConnection("localhost", 389, "cn=admin", "pass");
            assertThat(conn).isNotNull();
            assertThat(mocked.constructed()).hasSize(1);
            verify(mocked.constructed().get(0)).bind("cn=admin", "pass");
        }
    }

    @Test
    @DisplayName("openConnection throws LdapConnectionException on bind failure")
    void testOpenConnectionBindFailure() throws Exception {
        try (MockedConstruction<LdapNetworkConnection> mocked = mockConstruction(LdapNetworkConnection.class,
                (mock, ctx) -> {
                    try {
                        doThrow(new RuntimeException("bind failed")).when(mock).bind(anyString(), anyString());
                    } catch (Exception ignored) {
                    }
                })) {
            assertThatThrownBy(() ->
                    LdapConnectionUtils.openConnection("localhost", 389, "cn=admin", "pass"))
                    .isInstanceOf(LdapConnectionException.class)
                    .hasMessageContaining("LDAP connection open failure");
        }
    }

    @Test
    @DisplayName("closeConnection succeeds with valid connection")
    void testCloseConnectionSuccess() throws Exception {
        LdapConnection mockConn = mock(LdapConnection.class);
        LdapConnectionUtils.closeConnection(mockConn);
        verify(mockConn).unBind();
        verify(mockConn).close();
    }

    @Test
    @DisplayName("closeConnection throws LdapConnectionException on unBind failure")
    void testCloseConnectionUnbindFailure() throws Exception {
        LdapConnection mockConn = mock(LdapConnection.class);
        doThrow(new RuntimeException("unbind error")).when(mockConn).unBind();
        assertThatThrownBy(() -> LdapConnectionUtils.closeConnection(mockConn))
                .isInstanceOf(LdapConnectionException.class)
                .hasMessageContaining("LDAP connection close failure");
    }

    @Test
    @DisplayName("closeConnection throws LdapConnectionException on close failure")
    void testCloseConnectionCloseFailure() throws Exception {
        LdapConnection mockConn = mock(LdapConnection.class);
        doThrow(new RuntimeException("close error")).when(mockConn).close();
        assertThatThrownBy(() -> LdapConnectionUtils.closeConnection(mockConn))
                .isInstanceOf(LdapConnectionException.class)
                .hasMessageContaining("LDAP connection close failure");
    }

    @Test
    @DisplayName("LdapConnectionUtils class has expected methods")
    void testClassStructure() throws NoSuchMethodException {
        assertThat(LdapConnectionUtils.class.getMethod("openConnection",
                String.class, int.class, String.class, String.class)).isNotNull();
        assertThat(LdapConnectionUtils.class.getMethod("closeConnection",
                LdapConnection.class)).isNotNull();
    }
}
