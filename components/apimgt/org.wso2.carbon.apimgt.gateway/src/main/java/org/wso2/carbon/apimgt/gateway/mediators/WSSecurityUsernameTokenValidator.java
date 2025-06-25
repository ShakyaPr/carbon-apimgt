/*
 * Copyright (c) 2025 WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 *
 */
package org.wso2.carbon.apimgt.gateway.mediators;

import org.apache.axiom.om.OMAttribute;
import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.OMNamespace;
import org.apache.axiom.soap.*;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.synapse.Mediator;
import org.apache.synapse.MessageContext;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.apache.synapse.mediators.AbstractMediator;
import org.apache.synapse.transport.passthru.util.RelayUtils;

import javax.jms.Message;
import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import java.io.IOException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

public class WSSecurityUsernameTokenValidator extends AbstractMediator {
    private static final Log logger = LogFactory.getLog(WSSecurityUsernameTokenValidator.class);
    private static final String WSSE_NS = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
    private static final String WSU_NS = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
    private static final String WSSE_PREFIX = "wsse";
    private static final ConcurrentMap<String, String> userStore = new ConcurrentHashMap<>();
    static {
        // Initialize user store (replace with database lookup in production)
        userStore.put("dda_user1", "dda_pass1");
        userStore.put("dda_user2", "dda_pass2");
        userStore.put("admin", "admin");
        userStore.put("ShakyaPr", "ShakyaPr");
        userStore.put("testuser", "admin");
    }
    @Override
    public boolean mediate(MessageContext messageContext) {
        WSSecurityToken wsSecurityToken = extractSecurityToken(messageContext);
        if (wsSecurityToken == null) {
            logger.error("Failed to extract WS-Security token from the message context");
            sendAuthFailure(messageContext, "WS_SECURITY_HEADER_MISSING",
                    "WS-Security UsernameToken header is required", null);
            return false;
        }
        boolean isAuthenticated = validateWSSecurityToken(wsSecurityToken);
        if (!isAuthenticated) {
            logger.error("WS-Security token validation failed for user: " + wsSecurityToken.getUsername());
            sendAuthFailure(messageContext, "AUTHENTICATION_FAILED",
                    "Invalid WS-Security UsernameToken credentials", wsSecurityToken.getUsername());
            return false;
        }
        logger.info("WS-Security authentication successful for user: " + wsSecurityToken.getUsername());
        return true;
    }
    private void sendAuthFailure(MessageContext messageContext, String errorCode, String errorMessage, String username) {
        messageContext.setProperty("ERROR_CODE", errorCode);
        messageContext.setProperty("ERROR_MESSAGE", errorMessage);

        String faultMedName = constructFaultSeqKey(messageContext);
        Mediator faultMediator = (Mediator) messageContext.getConfiguration()
                .getLocalRegistry().get(faultMedName);
        if (faultMediator == null) {
            faultMediator = messageContext.getFaultSequence();
        }
        faultMediator.mediate(messageContext);

    }
    private String constructFaultSeqKey(MessageContext mc) {
        // Retrieve API Name
        String apiName = (String) mc.getProperty("api.ut.api");
        // Retrieve API Version
        String apiVersion = (String) mc.getProperty("api.ut.version");

        log.debug("Constructing fault sequence name for API: " + apiName + ", Version: " + apiVersion);

        // Construct the fault sequence key
        return apiName + ":v" + apiVersion + "--Fault";
    }

    private WSSecurityToken extractSecurityToken(MessageContext messageContext) {
        try {
            RelayUtils.buildMessage(((Axis2MessageContext) messageContext).getAxis2MessageContext());
        } catch (IOException | XMLStreamException e) {
            logger.error("Error building message context", e);
            return null;
        }
        SOAPEnvelope envelope = messageContext.getEnvelope();
        if (envelope == null) {
            logger.error("SOAP Envelope is null");
            return null;
        }
        SOAPHeader header = envelope.getHeader();
        if (header == null) {
            logger.error("SOAP Header is null");
            return null;
        }
        OMElement securityElement = header.getFirstChildWithName(
                new QName(WSSE_NS, "Security", WSSE_PREFIX));
        if (securityElement == null) {
            logger.error("WS-Security header is missing");
            return null;
        }
        OMElement usernameTokenElement = securityElement.getFirstChildWithName(
                new QName(WSSE_NS, "UsernameToken", WSSE_PREFIX));
        if (usernameTokenElement == null) {
            logger.error("UsernameToken element is missing in WS-Security header");
            return null;
        }
        WSSecurityToken token = new WSSecurityToken();

        OMAttribute idAttribute = usernameTokenElement.getAttribute(
                new QName(WSU_NS, "Id", WSSE_PREFIX));
        if (idAttribute != null) {
            token.setId(idAttribute.getAttributeValue());
        } else {
            logger.warn("UsernameToken does not have an Id attribute");
        }

        OMElement usernameElement = usernameTokenElement.getFirstChildWithName(
                new QName(WSSE_NS, "Username", "wsse"));
        if (usernameElement != null) {
            token.setUsername(usernameElement.getText());
        }

        OMElement passwordElement = usernameTokenElement.getFirstChildWithName(
                new QName(WSSE_NS, "Password", "wsse"));
        if (passwordElement != null) {
            token.setPassword(passwordElement.getText());
            OMAttribute typeAttr = passwordElement.getAttribute(new QName("Type"));
            if (typeAttr != null) {
                token.setPasswordType(typeAttr.getAttributeValue());
            }
        }
        OMElement nonceElement = usernameTokenElement.getFirstChildWithName(
                new QName(WSSE_NS, "Nonce", "wsse"));
        if (nonceElement != null) {
            token.setNonce(nonceElement.getText());
            OMAttribute encodingAttr = nonceElement.getAttribute(new QName("EncodingType"));
            if (encodingAttr != null) {
                token.setNonceEncodingType(encodingAttr.getAttributeValue());
            }
        }

        // Created timestamp
        OMElement createdElement = usernameTokenElement.getFirstChildWithName(
                new QName(WSU_NS, "Created", "wsu"));
        if (createdElement != null) {
            token.setCreated(createdElement.getText());
        }

        if (logger.isDebugEnabled()) {
            logger.debug("WS-Security token extracted successfully for user: " + token.getUsername());
            logger.debug("Token ID: " + token.getId());
            logger.debug("Password Type: " + token.getPasswordType());
            logger.debug("Has Nonce: " + (token.getNonce() != null));
            logger.debug("Has Timestamp: " + (token.getCreated() != null));
        }
        return token;
    }
//    private void  handleAuthenticationFailure(MessageContext messageContext, String errorCode,
//            String errorMessage, String username) {
//        try {
//            logger.error("=== Authentication Failure Handler ===");
//            logger.error("Error Code: " + errorCode);
//            logger.error("Error Message: " + errorMessage);
//            logger.error("Failed User: " + (username != null ? username : "Unknown"));
//            // Set HTTP 401 status code
//            org.apache.axis2.context.MessageContext axis2MC =
//                    ((Axis2MessageContext) messageContext).getAxis2MessageContext();
//            axis2MC.setProperty("HTTP_SC", 401);
//
//            // Set error properties in message context
//            messageContext.setProperty("ERROR_CODE", errorCode);
//            messageContext.setProperty("ERROR_MESSAGE", errorMessage);
//            messageContext.setProperty("FAILED_USER", username);
//
//            // Create SOAP fault response
//            createSOAPFaultResponse(messageContext, errorCode, errorMessage, username);
//
//            // Set response headers
//            setErrorResponseHeaders(axis2MC, errorCode, username);
//
//            // Mark message as fault response
//            messageContext.setFaultResponse(true);
//
//            logger.error("Authentication failure response created successfully");
//        } catch (Exception e) {
//            logger.error("Error creating authentication failure response: " + e.getMessage(), e);
//        }
//    }

    private boolean validateWSSecurityToken(WSSecurityToken token) {
        // Validate required fields
        if (token.getUsername() == null || token.getUsername().trim().isEmpty()) {
            logger.error("Username is missing in the WS-Security token");
            return false;
        }

        if (token.getPassword() == null || token.getPassword().trim().isEmpty()) {
            logger.error("Password is missing in the WS-Security token for user: " + token.getUsername());
            return false;
        }
        String password = userStore.get(token.getUsername());
        if (password == null) {
            logger.error("User not found or inactive: " + token.getUsername());
            return false;
        }
        if (!password.equals(token.getPassword())) {
            logger.error("Invalid password for user: " + token.getUsername());
            return false;
        }
        // Additional checks can be added here (e.g., nonce, timestamp)
        return true;
    }
    /**
     * Create SOAP fault response for authentication failure
     */
//    private void createSOAPFaultResponse(MessageContext messageContext, String errorCode,
//            String errorMessage, String username) {
//        try {
//            // Get SOAP factory
//            SOAPFactory soapFactory = (SOAPFactory) messageContext.getEnvelope().getOMFactory();
//
//            // Create new SOAP envelope for fault
//            SOAPEnvelope faultEnvelope = soapFactory.getDefaultEnvelope();
//
//            // Create SOAP fault
//            SOAPFault soapFault = soapFactory.createSOAPFault();
//
//            // Create fault code
//            SOAPFaultCode faultCode = soapFactory.createSOAPFaultCode();
//            faultCode.setText("soap:Client");
//            soapFault.setCode(faultCode);
//
//            // Create fault reason
//            SOAPFaultReason faultReason = soapFactory.createSOAPFaultReason();
//            faultReason.setText(getErrorDescription(errorCode));
//            soapFault.setReason(faultReason);
//
//            // Create fault detail
//            SOAPFaultDetail faultDetail = soapFactory.createSOAPFaultDetail();
//            OMElement errorElement = createErrorDetailElement(soapFactory, errorCode, errorMessage, username);
//            faultDetail.addChild(errorElement);
//            soapFault.setDetail(faultDetail);
//
//            // Add fault to envelope body
//            faultEnvelope.getBody().addChild(soapFault);
//
//            // Set the fault envelope
//            messageContext.setEnvelope(faultEnvelope);
//
//            logger.info("SOAP fault response created successfully");
//        } catch (Exception e) {
//            logger.error("Error creating SOAP fault response: " + e.getMessage(), e);
//        }
//    }
//
//    /**
//     * Create detailed error element for SOAP fault
//     */
//    private OMElement createErrorDetailElement(SOAPFactory factory, String errorCode,
//            String errorMessage, String username) {
//        try {
//            // Create custom namespace for error details
//            OMNamespace errorNS = factory.createOMNamespace("http://dda.gov.ae/apim/wssecurity/faults/v1", "err");
//
//            // Create error element
//            OMElement errorElement = factory.createOMElement("AuthenticationError", errorNS);
//
//            // Add error code
//            OMElement codeElement = factory.createOMElement("code", errorNS);
//            codeElement.setText(errorCode);
//            errorElement.addChild(codeElement);
//
//            // Add error message
//            OMElement messageElement = factory.createOMElement("message", errorNS);
//            messageElement.setText(errorMessage);
//            errorElement.addChild(messageElement);
//
//            // Add description
//            OMElement descriptionElement = factory.createOMElement("description", errorNS);
//            descriptionElement.setText(getErrorDescription(errorCode));
//            errorElement.addChild(descriptionElement);
//
//            // Add failed user if available
//            if (username != null) {
//                OMElement userElement = factory.createOMElement("failedUser", errorNS);
//                userElement.setText(username);
//                errorElement.addChild(userElement);
//            }
//
//            // Add timestamp
//            OMElement timestampElement = factory.createOMElement("timestamp", errorNS);
//            timestampElement.setText("2025-06-25 04:27:14");
//            errorElement.addChild(timestampElement);
//
//            // Add handler info
//            OMElement handlerElement = factory.createOMElement("handledBy", errorNS);
//            handlerElement.setText("ShakyaPr");
//            errorElement.addChild(handlerElement);
//
//            // Add system info
//            OMElement systemElement = factory.createOMElement("system", errorNS);
//            systemElement.setText("WSO2-APIM-Gateway");
//            errorElement.addChild(systemElement);
//
//            return errorElement;
//
//        } catch (Exception e) {
//            logger.error("Error creating error detail element: " + e.getMessage(), e);
//            return null;
//        }
//    }
//
//    /**
//     * Get human-readable error description
//     */
//    private String getErrorDescription(String errorCode) {
//        switch (errorCode) {
//        case "WS_SECURITY_HEADER_MISSING":
//            return "WS-Security UsernameToken header is required for authentication";
//        case "AUTHENTICATION_FAILED":
//            return "Authentication failed due to invalid credentials";
//        case "AUTHENTICATION_ERROR":
//            return "An internal error occurred during authentication";
//        default:
//            return "Authentication failed";
//        }
//    }
//
//    /**
//     * Set error response headers
//     */
//    private void setErrorResponseHeaders(org.apache.axis2.context.MessageContext axis2MC,
//            String errorCode, String username) {
//        try {
//            // Set custom error headers
//            axis2MC.setProperty("X-Authentication-Status", "FAILED");
//            axis2MC.setProperty("X-Error-Code", errorCode);
//
//            if (username != null) {
//                axis2MC.setProperty("X-Failed-User", username);
//            }
//
//            // Set WWW-Authenticate header for 401 response
//            axis2MC.setProperty("WWW-Authenticate", "WS-Security realm=\"DDA API Gateway\"");
//
//            // Set content type for SOAP fault
//            axis2MC.setProperty("Content-Type", "text/xml; charset=utf-8");
//
//            logger.info("Error response headers set successfully");
//        } catch (Exception e) {
//            logger.error("Error setting response headers: " + e.getMessage(), e);
//        }
//    }
    private static class WSSecurityToken {
        private String username;
        private String password;
        private String id;
        private String passwordType;
        private String nonce;
        private String nonceEncodingType;
        private String created;

        public WSSecurityToken() {}

        public WSSecurityToken(String username, String password) {
            this.username = username;
            this.password = password;
        }
        public void setUsername(String username) { this.username = username; }
        public String getUsername() { return username; }
        public void setPassword(String password) { this.password = password; }
        public String getPassword() { return password; }
        public void setId(String id) { this.id = id; }
        public String getId() { return id; }
        public void setPasswordType(String passwordType) { this.passwordType = passwordType; }
        public String getPasswordType() { return passwordType; }
        public void setNonce(String nonce) { this.nonce = nonce; }
        public String getNonce() { return nonce; }
        public void setCreated(String created) { this.created = created; }
        public String getCreated() { return created; }
        private void setNonceEncodingType(String nonceEncodingType) {
            this.nonceEncodingType = nonceEncodingType;
        }
        private String getNonceEncodingType() {
            return nonceEncodingType;
        }
    }
}
