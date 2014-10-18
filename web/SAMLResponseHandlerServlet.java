package com.gs.ti.wpt.lc.login.web;


import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import com.gs.ti.wpt.lc.login.sso.*;
import com.gs.ti.wpt.lc.metadata.maestro.mongo.MongoMaestroFactory;
import com.gs.ti.wpt.lc.metadata.maestro.users.mongo.MongoMaestroUser;
import org.apache.commons.io.IOUtils;
import com.gs.ti.wpt.lc.metadata.maestro.ssoreplayprevention.MongoSSOReplayPreventionDAO;
import com.gs.ti.wpt.lc.metadata.maestro.exceptions.MaestroDBException;
import org.apache.commons.codec.binary.Base64;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServlet;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import com.gs.ti.wpt.lc.loginsecurity.SessionToken;
import com.gs.ti.wpt.lc.loginsecurity.SessionKeyManager;
import com.gs.ti.wpt.lc.loginsecurity.EncryptionException;




import com.gs.ti.wpt.lc.metadata.maestro.IUserDao;
/***
 * SAML Response Handler Servlet
 * @author Serkan
 *
 */
@WebServlet(name = "sso_acs", value = {"/sso/acs"}, loadOnStartup = 1)
public class SAMLResponseHandlerServlet extends HttpServlet { //will be HttpServlet
    private static final long serialVersionUID = 5234567895811254567L;
    private static final Logger LOG = LoggerFactory.getLogger(SAMLResponseHandlerServlet.class);
    private SessionKeyManager sessionKeyManager;
    private static final String SESSION_COOKIE = "skey";	//CONFIG_PARAMETER
    private static final String SESSION_COOKIE_PATH = "/";//CONFIG_PARAMETER
    private  UnmarshallerFactory unmarshallerFactory;
    private DocumentBuilderFactory documentBuilderFactory;
    private boolean isLibraryInit=false;
    private SSOReplayPreventionService replayPreventionService;
    private IUserDao userDao;
    @Override
    public void init(ServletConfig sc) throws ServletException {
        super.init(sc);

        try{
            sessionKeyManager = SessionKeyManager.instance();
        } catch (EncryptionException | IOException e){
            throw new ServletException("Unable to initialize SessionKeyManager", e);
        }
        MongoSSOReplayPreventionDAO rpdao = null;

        try {
            rpdao = (MongoSSOReplayPreventionDAO) MongoMaestroFactory.getMaestro().getSsoReplayPreventionDAO();

        } catch (MaestroDBException e) {
            e.printStackTrace();
        }
        try {
            userDao = MongoMaestroFactory.getMaestro().getUserDao();
        } catch (MaestroDBException e) {
            e.printStackTrace();
        }
        replayPreventionService=new SSOReplayPreventionService(rpdao);
        //init opensaml library
        LoadLibraryIfNotLoaded();
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException,
    IOException
    {
        LoadLibraryIfNotLoaded();
        String samlResponse=req.getParameter("SAMLResponse");
        String samlSubject=null;

        //resolve IdP from configuration
        SSOConfigurationHandler ssoConfig;
        try {
            ssoConfig = new SSOConfigurationHandler("default");
        } catch (SSOConfigurationException e) {
            ServletOutputStream os=resp.getOutputStream();
            os.print("SSO is not configured properly");
            os.flush();
            os.close();
            return;
        }

        if(samlResponse!=null && !samlResponse.equals("")) //Handle empty SAMLResponse as well
        {

            InputStream responseStream = null;
            try{
                // get response
                byte[] base64DecodedResponse = Base64.decodeBase64(samlResponse);
                responseStream = new ByteArrayInputStream(base64DecodedResponse);
                DocumentBuilder docBuilder = documentBuilderFactory.newDocumentBuilder();
                Document document = docBuilder.parse(responseStream);
                Element element = document.getDocumentElement();
                Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(element);
                XMLObject responseXmlObj = unmarshaller.unmarshall(element);

                IdpMetadata idpMetadata=ssoConfig.GetMetadata();

                SAMLAssertionValidator validator = new SAMLAssertionValidator(idpMetadata);
                Assertion assertion = validator.processResponse((org.opensaml.saml2.core.Response) responseXmlObj);
                samlSubject = validator.processAssertion(assertion);
                replayPreventionService.applyReplayPreventionCheck(validator.getAssertionIdFromAssertion(assertion), validator.getNotOnOrAfterFromAssertion(assertion).getMillis(), true);
            }
            catch(Exception e)
            {
                LOG.error("SAML Validation Error:", e);
                resp.sendRedirect(ssoConfig.getSymphonyBaseUrl()+"/login/sso/error?ErrorCode=2");
                return;
            }
            finally {
                IOUtils.closeQuietly(responseStream);
            }
            if(samlSubject!=null)
            {
                String tokenText;
                String userId;
                try {
                    MongoMaestroUser mmu=(MongoMaestroUser) userDao.getBySamlId(samlSubject,0,null);
                    userId=mmu.getUserId();
                    SessionToken sessionToken=new SessionToken(userId,System.currentTimeMillis());
                    tokenText = Base64.encodeBase64String(sessionKeyManager.encrypt(sessionToken.serializeToString()));
                } catch (MaestroDBException |EncryptionException e) {
                    resp.sendRedirect(ssoConfig.getSymphonyBaseUrl()+"/login/sso/error?ErrorCode=2");
                    return;
                }

                Cookie sessionCookie = new Cookie(SESSION_COOKIE, tokenText);
                sessionCookie.setDomain(ssoConfig.getSessionCookieDomain());
                sessionCookie.setPath(SESSION_COOKIE_PATH);
                sessionCookie.setMaxAge(-1);
                resp.addCookie(sessionCookie);
                LOG.debug("SAMLSubject="+ samlSubject+"  UserId="+userId+ "  logged in");
                resp.sendRedirect(ssoConfig.getSymphonyApplicationUrl()+ "/");
            }
            else
            {
                LOG.debug("SAML Validation Error");
                resp.sendRedirect(ssoConfig.getSymphonyBaseUrl()+"/login/sso/error?ErrorCode=2");
            }
        }
        else
        {
            LOG.debug("NO SAML assertions could be found!");
            resp.sendRedirect(ssoConfig.getSymphonyBaseUrl()+"/login/sso/error?ErrorCode=1");
        }
    }
    private void LoadLibraryIfNotLoaded() throws ServletException{
        if(!isLibraryInit)
        {
            try{
                OpenSamlBootstrap.bootstrap();
                this.unmarshallerFactory = Configuration.getUnmarshallerFactory();
                this.documentBuilderFactory = DocumentBuilderFactory.newInstance();
                documentBuilderFactory.setNamespaceAware(true);
                isLibraryInit=true;
            }
            catch (ConfigurationException e1) {
                throw new ServletException();
            }
        }
    }
}

