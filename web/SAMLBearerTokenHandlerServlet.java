package com.gs.ti.wpt.lc.login.web;



import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;


import com.gs.ti.wpt.lc.login.sso.*;
import com.gs.ti.wpt.lc.metadata.maestro.IUserDao;
import com.gs.ti.wpt.lc.metadata.maestro.mongo.MongoMaestroFactory;
import com.gs.ti.wpt.lc.metadata.maestro.users.mongo.MongoMaestroUser;
import org.apache.commons.io.IOUtils;


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

import com.gs.ti.wpt.lc.metadata.maestro.ssoreplayprevention.MongoSSOReplayPreventionDAO;


/***
 * SAML Assertion Handler Servlet
 * @author Serkan
 *
 */

// This will be the token endpoint and eventually it would support authentication types other than SAML Bearer Token
@WebServlet(name = "sso_token", value = {"/sso/token"}, loadOnStartup = 1)
public class SAMLBearerTokenHandlerServlet extends HttpServlet { //will be HttpServlet
	private static final long serialVersionUID = 5434567895811254567L;
	private static final Logger LOG = LoggerFactory.getLogger(SAMLBearerTokenHandlerServlet.class);
	private SessionKeyManager sessionKeyManager;
	private static final String SAML_BEARER_ASSERTION_TYPE="urn:ietf:params:oauth:grant-type:saml2-bearer";

	private  UnmarshallerFactory unmarshallerFactory;
	private DocumentBuilderFactory documentBuilderFactory;
	private boolean isLibraryInit=false;
	private SSOReplayPreventionService replayPreventionService;
    private IUserDao userDao;
    private static final String SESSION_COOKIE = "skey";	//CONFIG_PARAMETER
    private static final String SESSION_COOKIE_PATH = "/";//CONFIG_PARAMETER
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
		String assertionString=req.getParameter("Assertion");
		String grant_type=req.getParameter("grant_type");
		String client_id=req.getParameter("client_id"); //user type defines
		String samlSubject=null;

		if(assertionString!=null && !assertionString.equals("") && grant_type!=null && grant_type.equals(SAML_BEARER_ASSERTION_TYPE) && client_id!=null && client_id.equals("user")) //Handle empty SAMLResponse as well
		{
			InputStream assertionStream = null;

            SSOConfigurationHandler ssoConfig;
            try {
                //resolve IdP from configuration
                ssoConfig = new SSOConfigurationHandler("default");
            } catch (SSOConfigurationException e) {
                ServletOutputStream os=resp.getOutputStream();
                os.print(JSONStringErrorMessage("Configuration Error","SAML assertion authentication is not configured properly"));
                os.flush();
                os.close();
                return;
            }
			try{
			    //get assertion
				byte[] base64DecodedAssertion = Base64.decodeBase64(assertionString);
				assertionStream = new ByteArrayInputStream(base64DecodedAssertion);
				DocumentBuilder docBuilder = documentBuilderFactory.newDocumentBuilder();
				Document document = docBuilder.parse(assertionStream);
				Element element = document.getDocumentElement();
				Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(element);
				XMLObject assertionXmlObj = unmarshaller.unmarshall(element);
				Assertion assertion=(Assertion) assertionXmlObj;
				IdpMetadata idpMetadata=ssoConfig.GetMetadata(); //SSO configuration, idpEntityId is dummy, required for public pod, IdP resolution
				SAMLAssertionValidator validator = new SAMLAssertionValidator(idpMetadata);
				samlSubject = validator.processAssertion(assertion);	
				replayPreventionService.applyReplayPreventionCheck(validator.getAssertionIdFromAssertion(assertion), validator.getNotOnOrAfterFromAssertion(assertion).getMillis(), true);
			}   
			catch(Exception e)
			{
                LOG.debug("Exception during validation:" + e.getMessage());
				resp.setContentType("application/json");
				resp.setStatus(401);
				ServletOutputStream os=resp.getOutputStream();
				os.print(JSONStringErrorMessage("ValidationError","SAML Assertion could not be verified"));
				os.flush();
				os.close();
				return;
			}
			finally {
				IOUtils.closeQuietly(assertionStream);
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
                } catch (MaestroDBException | EncryptionException e) {
                    ServletOutputStream os=resp.getOutputStream();
                    os.print(JSONStringErrorMessage("ServerError","Internal server error"));
                    os.flush();
                    os.close();
                    return;
                }
                //setting cookie as well based on GS' request
                Cookie sessionCookie = new Cookie(SESSION_COOKIE, tokenText);
                sessionCookie.setDomain(ssoConfig.getSessionCookieDomain());
                sessionCookie.setPath(SESSION_COOKIE_PATH);
                sessionCookie.setMaxAge(-1);
                resp.addCookie(sessionCookie);
                LOG.debug("SAMLSubject="+ samlSubject+"  UserId="+userId+ "  logged in");

				resp.setContentType("application/json");
				resp.setStatus(200);
				ServletOutputStream os=resp.getOutputStream();
				os.print("{\"token\":\""+tokenText+"\"}");
				os.flush();
				os.close();

			}
			else
			{
				ServletOutputStream os=resp.getOutputStream();
				os.print(JSONStringErrorMessage("ValidationError","SAML Assertion could not be verified"));
				os.flush();
				os.close();
			}
		}
		else
		{
			LOG.debug("NO SAML assertions could be found!");
			resp.setContentType("application/json");
			resp.setStatus(401);
			ServletOutputStream os=resp.getOutputStream();
			os.print(JSONStringErrorMessage("BadRequest","Missing Parameters"));
			os.flush();
			os.close();
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
	private String JSONStringErrorMessage(String error, String errorMessage)
	{		
		return "{\"error\":\"" + error+"\",\"error_description\":\""+errorMessage+"\"}";
	}
}

