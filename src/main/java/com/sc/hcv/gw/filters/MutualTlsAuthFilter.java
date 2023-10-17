package com.sc.hcv.gw.filters;

import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;
import org.springframework.stereotype.Component;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.servlet.http.HttpServletRequest;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.stream.Stream;

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

         /*
           Additional validations on the certficates.

           Certs shoud be issued with CN  always be in the format appname.environment.domain.com,
           where appname is the name of the application,
           environment could be dev, staging, prod, etc., and
           domain.com is your organization's domain.

           Check the certificate's Common Name based on to whom it was issued and whitelist accordingly.
         */

        try {
            LdapName ldapName = new LdapName(clientCert.getSubjectX500Principal().getName());
            List<Rdn> rdns = ldapName.getRdns();
            Stream<Rdn> rdnStream = rdns.stream();
            Stream<Rdn> cnStream = rdnStream.filter(rdn -> rdn.getType().equalsIgnoreCase("CN"));
            Stream<String> cnValueStream = cnStream.map(rdn -> rdn.getValue().toString());
            String cn = cnValueStream.findFirst().orElse(null);
        }
        catch(InvalidNameException exception){
            ctx.setSendZuulResponse(false);
            ctx.setResponseStatusCode(403);
            ctx.setResponseBody("Invalid Common Name in the Cert from Client");
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

