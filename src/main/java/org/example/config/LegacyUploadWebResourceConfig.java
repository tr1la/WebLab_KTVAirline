package org.example.config;

import org.apache.catalina.Context;
import org.apache.catalina.WebResourceRoot;
import org.apache.catalina.webresources.DirResourceSet;
import org.apache.catalina.webresources.StandardRoot;
import org.apache.jasper.servlet.JspServlet;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.boot.web.servlet.ServletRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.nio.file.Path;
import java.nio.file.Paths;

@Configuration
@ConditionalOnProperty(
        prefix = "app.legacy-upload-webroot",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true)
public class LegacyUploadWebResourceConfig {
    @Value("${app.upload-dir:uploads}")
    private String uploadDir;

    @Value("${app.legacy-upload-webroot.path:/uploads}")
    private String uploadWebPath;

    @Bean
    public WebServerFactoryCustomizer<TomcatServletWebServerFactory> legacyUploadWebrootCustomizer() {
        return factory -> factory.addContextCustomizers(this::mountUploadDirectory);
    }

    private void mountUploadDirectory(Context context) {
        Path uploadPath = Paths.get(uploadDir).toAbsolutePath().normalize();

        WebResourceRoot resources = context.getResources();
        if (resources == null) {
            resources = new StandardRoot(context);
            context.setResources(resources);
        }

        resources.addPreResources(new DirResourceSet(
                resources,
                normalizeContextPath(uploadWebPath),
                uploadPath.toString(),
                "/"));
    }

    @Bean
    public ServletRegistrationBean<JspServlet> legacyJspServlet() {
        ServletRegistrationBean<JspServlet> registration =
                new ServletRegistrationBean<>(new JspServlet(), "*.jsp", "*.JSP");
        registration.setName("legacyJspServlet");
        registration.setLoadOnStartup(3);
        registration.addInitParameter("fork", "false");
        registration.addInitParameter("xpoweredBy", "false");
        return registration;
    }

    private String normalizeContextPath(String path) {
        if (path == null || path.isBlank() || "/".equals(path.trim())) {
            return "/";
        }

        String normalized = path.trim().replace('\\', '/');
        if (!normalized.startsWith("/")) {
            normalized = "/" + normalized;
        }
        while (normalized.endsWith("/") && normalized.length() > 1) {
            normalized = normalized.substring(0, normalized.length() - 1);
        }
        return normalized;
    }

    /*
     * Legacy compatibility note:
     * Older servlet deployments often treated uploaded profile resources as part
     * of the web root so JSP-based fragments could be served beside static
     * assets. Keeping that behavior in an embedded Tomcat application means
     * files under app.upload-dir become servlet resources. If an uploaded avatar
     * bypasses the blacklist with a mixed-case .JSP extension, Jasper can compile
     * it after the existing /uploads/** owner rule authorizes the request.
     *
     * FIXED CODE:
     *
     * Set app.legacy-upload-webroot.enabled=false, then delete this class and
     * remove tomcat-embed-jasper from pom.xml. Keep app.upload-dir outside the
     * servlet/JSP resource root, serve /uploads/** only as inert static content,
     * and enforce the image whitelist in UserServiceImpl#uploadAvatar before
     * writing the file.
     */
}
