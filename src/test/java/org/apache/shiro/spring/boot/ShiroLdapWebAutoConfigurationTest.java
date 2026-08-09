package org.apache.shiro.spring.boot;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("ShiroLdapWebAutoConfiguration Tests")
class ShiroLdapWebAutoConfigurationTest {

    @Test
    @DisplayName("Auto-configuration class can be instantiated")
    void testInstantiation() {
        ShiroLdapWebAutoConfiguration configuration = new ShiroLdapWebAutoConfiguration();
        assertThat(configuration).isNotNull();
    }

    @Test
    @DisplayName("Has correct conditional annotation")
    void testConditionalOnProperty() {
        ConditionalOnProperty annotation =
                ShiroLdapWebAutoConfiguration.class.getAnnotation(ConditionalOnProperty.class);
        assertThat(annotation).isNotNull();
        assertThat(annotation.prefix()).isEqualTo("shiro.ldap");
        assertThat(annotation.value()).containsExactly("enabled");
        assertThat(annotation.havingValue()).isEqualTo("true");
    }

    @Test
    @DisplayName("Enables ShiroLdapProperties")
    void testEnableConfigurationProperties() {
        EnableConfigurationProperties annotation =
                ShiroLdapWebAutoConfiguration.class.getAnnotation(EnableConfigurationProperties.class);
        assertThat(annotation).isNotNull();
        assertThat(annotation.value()).contains(ShiroLdapProperties.class);
    }

    @Test
    @DisplayName("Has ApplicationContextAware implemented")
    void testApplicationContextAware() {
        assertThat(ApplicationContextAware.class.isAssignableFrom(
                ShiroLdapWebAutoConfiguration.class)).isTrue();
    }

    @Test
    @DisplayName("setApplicationContext and getApplicationContext work")
    void testApplicationContext() {
        ShiroLdapWebAutoConfiguration config = new ShiroLdapWebAutoConfiguration();
        assertThat(config.getApplicationContext()).isNull();
        ApplicationContext mockCtx = org.mockito.Mockito.mock(ApplicationContext.class);
        config.setApplicationContext(mockCtx);
        assertThat(config.getApplicationContext()).isEqualTo(mockCtx);
    }

    @Test
    @DisplayName("Has @AutoConfigureBefore annotation")
    void testAutoConfigureBefore() {
        AutoConfigureBefore annotation =
                ShiroLdapWebAutoConfiguration.class.getAnnotation(AutoConfigureBefore.class);
        assertThat(annotation).isNotNull();
    }
}
