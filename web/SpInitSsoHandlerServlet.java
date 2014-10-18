package com.gs.ti.wpt.lc.login.web;


import com.gs.ti.wpt.lc.login.sso.IdpMetadata;
import com.gs.ti.wpt.lc.login.sso.SAMLRequestGenerator;
import com.gs.ti.wpt.lc.login.sso.SSOConfigurationException;
import com.gs.ti.wpt.lc.login.sso.SSOConfigurationHandler;



import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServlet;


import java.io.IOException;

/***
 * SAML Response Handler Servlet
 * @author Serkan
 *
 */
@WebServlet(name = "sso_sp_init", value = {"/sso/initsso"}, loadOnStartup = 1)
public class SpInitSsoHandlerServlet extends HttpServlet {
	private static final long serialVersionUID = 5234567895811253457L;
	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException,
	IOException {
        //resolve IdP from configuration
        SSOConfigurationHandler ssoConfig= null;
        try {
            ssoConfig = new SSOConfigurationHandler("default");
        } catch (SSOConfigurationException e) {
            ServletOutputStream os=resp.getOutputStream();
            os.print("SSO is not configured properly");
            os.flush();
            os.close();
            return;
        }
		try{
			//resolveidp from request
			IdpMetadata im=ssoConfig.GetMetadata(); //SSO configuration, idpEntityId is dummy, required for public pod, IdP resolution
            if(im.getIdpSSOEndpoint()==null || im.getIdpSSOEndpoint().equals(""))
            {
                resp.sendRedirect(ssoConfig.getSymphonyBaseUrl()+"/login/sso/error?ErrorCode=3");
                return;
            }
			SAMLRequestGenerator samlRequestGenerator=new SAMLRequestGenerator();
			String redirectURL=samlRequestGenerator.getAuthenticationRedirectURL(im);//
			resp.sendRedirect(redirectURL);

		}
		catch(IllegalArgumentException | SecurityException e)
		{
			resp.sendRedirect(ssoConfig.getSymphonyBaseUrl()+"/login/sso/error?ErrorCode=3");

		}
	}
}