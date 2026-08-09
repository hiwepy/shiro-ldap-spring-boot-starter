package org.apache.shiro.spring.boot;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("ShiroLdapWebFilterConfiguration Tests")
class ShiroLdapWebFilterConfigurationTest {

    @Test
    @DisplayName("Instance can be created via constructor")
    void testInstantiation() {
        ShiroLdapWebFilterConfiguration instance = new ShiroLdapWebFilterConfiguration();
        assertThat(instance).isNotNull();
    }

    @Test
    @DisplayName("Has @Configuration annotation")
    void testConfigurationAnnotation() {
        assertThat(ShiroLdapWebFilterConfiguration.class.getAnnotation(
                org.springframework.context.annotation.Configuration.class)).isNotNull();
    }

    @Test
    @DisplayName("Has @ConditionalOnProperty annotation with correct prefix")
    void testConditionalOnProperty() {
        ConditionalOnProperty annotation = ShiroLdapWebFilterConfiguration.class.getAnnotation(
                ConditionalOnProperty.class);
        assertThat(annotation).isNotNull();
        assertThat(annotation.prefix()).isEqualTo("shiro.ldap");
        assertThat(annotation.havingValue()).isEqualTo("true");
    }

    @Test
    @DisplayName("Implements ApplicationContextAware")
    void testApplicationContextAware() {
        assertThat(ApplicationContextAware.class.isAssignableFrom(
                ShiroLdapWebFilterConfiguration.class)).isTrue();
    }

    @Test
    @DisplayName("setApplicationContext and getApplicationContext work")
    void testApplicationContext() {
        ShiroLdapWebFilterConfiguration config = new ShiroLdapWebFilterConfiguration();
        assertThat(config.getApplicationContext()).isNull();
        // Create a minimal mock context
        ApplicationContext mockCtx = org.mockito.Mockito.mock(ApplicationContext.class);
        config.setApplicationContext(mockCtx);
        assertThat(config.getApplicationContext()).isEqualTo(mockCtx);
    }

    @Test
    @DisplayName("Has @AutoConfigureBefore annotation")
    void testAutoConfigureBefore() {
        AutoConfigureBefore annotation = ShiroLdapWebFilterConfiguration.class.getAnnotation(
                AutoConfigureBefore.class);
        assertThat(annotation).isNotNull();
        assertThat(annotation.name()).contains(
                "org.apache.shiro.spring.config.web.autoconfigure.ShiroWebFilterConfiguration",
                "org.apache.shiro.spring.boot.ShiroBizWebFilterConfiguration");
    }

    @Test
    @DisplayName("Has @EnableConfigurationProperties annotation")
    void testEnableConfigurationProperties() {
        EnableConfigurationProperties annotation = ShiroLdapWebFilterConfiguration.class.getAnnotation(
                EnableConfigurationProperties.class);
        assertThat(annotation).isNotNull();
        assertThat(annotation.value()).contains(ShiroLdapProperties.class);
    }

    @Test
    @DisplayName("Has @ConditionalOnProperty with value 'enabled'")
    void testConditionalOnPropertyValue() {
        ConditionalOnProperty annotation = ShiroLdapWebFilterConfiguration.class.getAnnotation(
                ConditionalOnProperty.class);
        assertThat(annotation.value()).containsExactly("enabled");
    }
}
