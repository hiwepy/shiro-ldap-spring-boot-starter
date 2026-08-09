package org.apache.shiro.spring.boot;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("ShiroLdapProperties Tests")
class ShiroLdapPropertiesTest {

    @Test
    @DisplayName("Default values are correct")
    void testDefaults() {
        ShiroLdapProperties props = new ShiroLdapProperties();
        assertThat(props.isEnabled()).isFalse();
        assertThat(props.isUseSsl()).isFalse();
        assertThat(props.getLdapPort()).isZero();
        assertThat(props.getLdapHost()).isNull();
        assertThat(props.getName()).isNull();
        assertThat(props.getCredentials()).isNull();
        assertThat(props.getEnabledCipherSuites()).isNull();
        assertThat(props.getSslProtocol()).isNotNull();
    }

    @Test
    @DisplayName("PREFIX constant has expected value")
    void testPREFIXConstant() {
        assertThat(ShiroLdapProperties.PREFIX).isEqualTo("shiro.ldap");
    }

    @Test
    @DisplayName("enabled getter/setter")
    void testEnabled() {
        ShiroLdapProperties props = new ShiroLdapProperties();
        props.setEnabled(true);
        assertThat(props.isEnabled()).isTrue();
        props.setEnabled(false);
        assertThat(props.isEnabled()).isFalse();
    }

    @Test
    @DisplayName("useSsl getter/setter")
    void testUseSsl() {
        ShiroLdapProperties props = new ShiroLdapProperties();
        props.setUseSsl(true);
        assertThat(props.isUseSsl()).isTrue();
    }

    @Test
    @DisplayName("ldapPort getter/setter")
    void testLdapPort() {
        ShiroLdapProperties props = new ShiroLdapProperties();
        props.setLdapPort(389);
        assertThat(props.getLdapPort()).isEqualTo(389);
    }

    @Test
    @DisplayName("ldapHost getter/setter")
    void testLdapHost() {
        ShiroLdapProperties props = new ShiroLdapProperties();
        props.setLdapHost("ldap://localhost");
        assertThat(props.getLdapHost()).isEqualTo("ldap://localhost");
    }

    @Test
    @DisplayName("name getter/setter")
    void testName() {
        ShiroLdapProperties props = new ShiroLdapProperties();
        props.setName("cn=admin");
        assertThat(props.getName()).isEqualTo("cn=admin");
    }

    @Test
    @DisplayName("credentials getter/setter")
    void testCredentials() {
        ShiroLdapProperties props = new ShiroLdapProperties();
        props.setCredentials("secret");
        assertThat(props.getCredentials()).isEqualTo("secret");
    }

    @Test
    @DisplayName("enabledCipherSuites getter/setter")
    void testEnabledCipherSuites() {
        ShiroLdapProperties props = new ShiroLdapProperties();
        String[] suites = {"TLS_RSA_WITH_AES_128_CBC_SHA"};
        props.setEnabledCipherSuites(suites);
        assertThat(props.getEnabledCipherSuites()).isEqualTo(suites);
    }

    @Test
    @DisplayName("sslProtocol getter/setter")
    void testSslProtocol() {
        ShiroLdapProperties props = new ShiroLdapProperties();
        props.setSslProtocol("SSLv3");
        assertThat(props.getSslProtocol()).isEqualTo("SSLv3");
    }
}
