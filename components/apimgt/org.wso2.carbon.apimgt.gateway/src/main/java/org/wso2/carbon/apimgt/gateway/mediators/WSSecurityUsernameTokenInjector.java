package org.wso2.carbon.apimgt.gateway.mediators;

import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.OMFactory;
import org.apache.axiom.om.OMNamespace;
import org.apache.axiom.soap.SOAPEnvelope;
import org.apache.axiom.soap.SOAPFactory;
import org.apache.axiom.soap.SOAPHeader;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.synapse.MessageContext;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.apache.synapse.mediators.AbstractMediator;
import org.apache.synapse.transport.passthru.util.RelayUtils;

import javax.xml.namespace.QName;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;
import java.util.UUID;

/**
 * Mediator to inject WS-Security Username Token into the SOAP header.
 * This mediator retrieves the username and password from the message context
 * and constructs a WS-Security Username Token element in the SOAP header.
 */
public class WSSecurityUsernameTokenInjector extends AbstractMediator {

    private static final Log logger = LogFactory.getLog(WSSecurityUsernameTokenInjector.class);
    private static final String WSSE_NS = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
    private static final String WSU_NS = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
    @Override
    public boolean mediate(MessageContext messageContext) {
        try {
            String username = (String) messageContext.getProperty("wsSecurityUsername");
            String password = (String) messageContext.getProperty("wsSecurityPassword");

            RelayUtils.buildMessage(((Axis2MessageContext) messageContext).getAxis2MessageContext());
            SOAPEnvelope soapEnvelope = messageContext.getEnvelope();

            if (soapEnvelope == null) {
                logger.error("SOAP Envelope is null. Cannot inject WS-Security Username Token.");
                return false;
            }
            SOAPFactory factory = (SOAPFactory) soapEnvelope.getOMFactory();

            OMNamespace wsseNamespace = factory.createOMNamespace(WSSE_NS, "wsse");
            OMNamespace wsuNamespace = factory.createOMNamespace(WSU_NS, "wsu");

            SOAPHeader soapHeader = soapEnvelope.getHeader();
            if (soapHeader == null) {
                soapHeader = factory.createSOAPHeader(soapEnvelope);
                soapEnvelope.addChild(soapHeader);
            }
            OMElement oldSec = soapHeader.getFirstChildWithName(
                    new QName(WSSE_NS, "Security", "wsse"));

            if (oldSec != null) {
                oldSec.detach();
            }

            OMElement securityElement = factory.createOMElement("Security", wsseNamespace);
            OMElement usernameTokenElement = factory.createOMElement("UsernameToken", wsseNamespace);
            usernameTokenElement.addAttribute("Id", "UsernameToken-" + UUID.randomUUID(), wsuNamespace);

            OMElement usernameElement = factory.createOMElement("Username", wsseNamespace);
            usernameElement.setText(username);
            usernameTokenElement.addChild(usernameElement);

            OMElement passwordElement = factory.createOMElement("Password", wsseNamespace);
            passwordElement.setText(password);
            usernameTokenElement.addChild(passwordElement);

            OMElement createdElem = factory.createOMElement("Created", wsuNamespace);
            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");
            sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
            createdElem.setText(sdf.format(new Date()));
            usernameTokenElement.addChild(createdElem);

            securityElement.addChild(usernameTokenElement);

            soapHeader.addChild(securityElement);

            logger.info("WS-Security UsernameToken header injected for user : " + username);
            return true;

        } catch (Exception e) {
            logger.error("Error while injecting WS-Security Username Token", e);
            return false;
        }
    }
}
