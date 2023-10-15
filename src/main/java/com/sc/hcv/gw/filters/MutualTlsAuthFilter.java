package com.sc.hcv.gw.filters;

import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import java.security.cert.X509Certificate;

@Component
public class MutualTlsAuthFilter extends ZuulFilter {

    @Override
    public String filterType() {
        return "pre";
    }

    @Override
    public int filterOrder() {
        return 1; // setting order to 1, but adjust as per your needs
    }

    @Override
    public boolean shouldFilter() {
        return true; // apply this filter to all requests
    }

    @Override
    public Object run() {
        RequestContext ctx = RequestContext.getCurrentContext();
        HttpServletRequest request = ctx.getRequest();

        X509Certificate[] certs = (X509Certificate[]) request.getAttribute("javax.servlet.request.X509Certificate");

        if (certs == null || certs.length == 0) {
            ctx.setSendZuulResponse(false); // don't forward request to service
            ctx.setResponseStatusCode(403); // forbidden
            ctx.setResponseBody("Missing client certificate");
            return null;
        }

        X509Certificate clientCert = certs[0];

     // Additional validations on the certficates.
     // Check the certificate's subject based on to whom it was issued and whitelist accordingly.
        String subject = clientCert.getSubjectDN().getName();
        String expectedSubject = "";
        if (!expectedSubject.equals(subject)) {
            ctx.setSendZuulResponse(false);
            ctx.setResponseStatusCode(403);
            ctx.setResponseBody("Invalid certificate subject");
            return null;
        }

     // Check the certificate's issuer based on to whom it was issued and whitelist accordingly.

        String issuer = clientCert.getIssuerDN().getName();
        String expectedIssuer = "";

        if (!expectedIssuer.equals(issuer)) {
            ctx.setSendZuulResponse(false);
            ctx.setResponseStatusCode(403);
            ctx.setResponseBody("Invalid certificate issuer");
            return null;
        }




        return null;
    }
}

