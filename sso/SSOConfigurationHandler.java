package com.gs.ti.wpt.lc.login.sso;


import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;

import javax.servlet.ServletException;

import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.File;
import java.security.KeyStoreException;
import java.security.NoSuchProviderException;
import java.security.NoSuchAlgorithmException;

//For now it is reading Configuration from file, when Admin API is finished, it will read it from MongoDB
public class SSOConfigurationHandler {
    private static final String SSO_CONFIG_FILE_LOCATION="SSOConfiguration.properties";
	private IdpMetadata idpMetadata;
	private String applicationUrl;
	private String sessionCookieDomain;
    private String baseUrl;
	
	private static final Logger LOG = LoggerFactory.getLogger(SSOConfigurationHandler.class);

	public SSOConfigurationHandler(String idpEntityId) throws SSOConfigurationException
	{

        try {
            getConfigurationFromFile();
        } catch (IOException e) {
            LOG.error("SSOConfiguration could not be loaded");
            throw new SSOConfigurationException("SSOConfiguration could not be loaded");
        }

	}
	public  IdpMetadata GetMetadata() throws ServletException
	{  
		return idpMetadata;	  
	}
	public String getSymphonyApplicationUrl()
	{
		return applicationUrl;
	}
    public String getSymphonyBaseUrl()
    {
        return baseUrl;
    }
	public String getSessionCookieDomain()
	{
		return sessionCookieDomain;
	}

    private void getConfigurationFromFile() throws IOException {
        ClassLoader cl = Thread.currentThread().getContextClassLoader();
        InputStream ssoConfigProps = cl.getResourceAsStream(SSO_CONFIG_FILE_LOCATION);


        Properties configProps = new Properties();
        configProps.load(ssoConfigProps);
        ssoConfigProps.close();

        this.applicationUrl=configProps.getProperty("symphony_applicationurl");
        this.baseUrl=configProps.getProperty("symphony_baseurl");
        this.sessionCookieDomain=configProps.getProperty("symphony_cookiedomain");
        String idpEntityId=configProps.getProperty("idp.entityid");
        String spEntityId=configProps.getProperty("symphony.entityid");
        String publicKeyFile=configProps.getProperty("idp.signingcertificate");
        String idpSSOEndpoint=configProps.getProperty("idp.ssoendpoint");
        String acsUrl=configProps.getProperty("symphony.acsurl");

        LOG.debug("App Url: "+this.applicationUrl+
                "\nCookie Domain: "+this.sessionCookieDomain+
                "\nIdp EntityId: "+idpEntityId+
                "\nSymphony Entity Id: "+spEntityId+
                "\nSigning Cert location: "+publicKeyFile+
                "\nIdP SSO Endpoint "+idpSSOEndpoint+
                "\n Symphony ACS URL: "+acsUrl);
        IdpMetadata im = new IdpMetadata();
        try{

            X509Certificate signingCertPubKey =readPublicKey(publicKeyFile,cl);
            //LOG.debug(signingCertPubKey.toString());
            im.setIdpEntityId(idpEntityId);
            im.setSpEntityId(spEntityId);
            im.setPublicKey(signingCertPubKey);
            im.setIdpSSOEndpoint(idpSSOEndpoint);
            im.setAcsUrl(acsUrl);
        }
        catch(Exception e)
        {
            //will be handled in the servlet as the invalidation of the assertion
            LOG.error("SEVERE: SAML SSO verification certificate could not be loaded");
            throw new IOException();
        }
        this.idpMetadata=im;

    }
    public static X509Certificate readPublicKey(String keyFile, ClassLoader cl) throws IOException, KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException, CertificateException
    {
        InputStream isPublicKeyFile = cl.getResourceAsStream(keyFile);
        try
        {
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            return (X509Certificate)certFactory.generateCertificate(isPublicKeyFile);
        }
        finally
        {
            IOUtils.closeQuietly(isPublicKeyFile);
        }
    }
}
