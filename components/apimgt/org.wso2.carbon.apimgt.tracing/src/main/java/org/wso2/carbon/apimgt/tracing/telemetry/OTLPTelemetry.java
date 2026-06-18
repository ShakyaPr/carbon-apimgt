/*
 * Copyright (c) 2022 WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
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
 */

package org.wso2.carbon.apimgt.tracing.telemetry;

import io.opentelemetry.api.OpenTelemetry;
import io.opentelemetry.api.trace.Tracer;
import io.opentelemetry.api.trace.propagation.W3CTraceContextPropagator;
import io.opentelemetry.context.propagation.ContextPropagators;
import io.opentelemetry.exporter.otlp.http.trace.OtlpHttpSpanExporter;
import io.opentelemetry.exporter.otlp.trace.OtlpGrpcSpanExporter;
import io.opentelemetry.sdk.OpenTelemetrySdk;
import io.opentelemetry.sdk.trace.SdkTracerProvider;
import io.opentelemetry.sdk.trace.export.BatchSpanProcessor;
import io.opentelemetry.sdk.trace.export.SpanExporter;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.apimgt.impl.APIManagerConfiguration;
import org.wso2.carbon.apimgt.tracing.internal.ServiceReferenceHolder;

import java.util.Set;

/**
 * Class for getting Otlp tracer from reading configuration file.
 */
public class OTLPTelemetry implements APIMOpenTelemetry {

    private static final String NAME = "otlp";
    private static final Log log = LogFactory.getLog(OTLPTelemetry.class);
    private static final APIManagerConfiguration configuration =
            ServiceReferenceHolder.getInstance().getAPIManagerConfiguration();
    private SdkTracerProvider sdkTracerProvider;
    private OpenTelemetry openTelemetry;

    @Override
    public void init(String serviceName) {
        String headerKey = null;
        String headerValue = null;

        String otlpProtocol = configuration.getFirstProperty(TelemetryConstants.OTLP_CONFIG_PROTOCOL) != null ?
                configuration.getFirstProperty(TelemetryConstants.OTLP_CONFIG_PROTOCOL) :
                TelemetryConstants.GRPC_PROTOCOL;
        String headerProperty = getHeaderKeyProperty();
        String endPointURL = configuration.getFirstProperty(TelemetryConstants.OTLP_CONFIG_URL) != null ?
                configuration.getFirstProperty(TelemetryConstants.OTLP_CONFIG_URL) : null;
        if (headerProperty != null) {
            headerKey = headerProperty.substring(TelemetryConstants.OPENTELEMETRY_PROPERTIES_PREFIX.length());

            headerValue = configuration.getFirstProperty(headerProperty) != null ?
                    configuration.getFirstProperty(headerProperty) : null;
        }

        boolean useHttp;
        if (TelemetryConstants.HTTP_PROTOCOL.equalsIgnoreCase(otlpProtocol)) {
            useHttp = true;
        } else if (TelemetryConstants.GRPC_PROTOCOL.equalsIgnoreCase(otlpProtocol)) {
            useHttp = false;
        } else {
            log.warn("OTLP protocol is not specified or is invalid. Defaulting to gRPC.");
            useHttp = false;
        }

        SpanExporter spanExporter;
        if (StringUtils.isNotEmpty(endPointURL)) {
            if (headerKey != null && headerValue != null) {
                if (useHttp) {
                    if (log.isDebugEnabled()) {
                        log.debug("OTLP HTTP exporter is configured at " + endPointURL +
                                " with header: " + headerKey + "=" + headerValue);
                    }
                    spanExporter = OtlpHttpSpanExporter.builder()
                            .setEndpoint(endPointURL)
                            .setCompression("gzip")
                            .addHeader(headerKey, headerValue)
                            .build();
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("OTLP gRPC exporter is configured at " + endPointURL +
                                " with header: " + headerKey + "=" + headerValue);
                    }
                    spanExporter = OtlpGrpcSpanExporter.builder()
                            .setEndpoint(endPointURL)
                            .setCompression("gzip")
                            .addHeader(headerKey, headerValue)
                            .build();
                }

            } else {
                if (useHttp) {
                    spanExporter = OtlpHttpSpanExporter.builder()
                            .setEndpoint(endPointURL)
                            .setCompression("gzip")
                            .build();
                    if (log.isDebugEnabled()) {
                        log.debug("OTLP exporter: " + spanExporter + " is configured at " + endPointURL +
                                " without headers.");
                    }
                } else {
                    spanExporter = OtlpGrpcSpanExporter.builder().setEndpoint(endPointURL)
                            .setCompression("gzip")
                            .build();
                    if (log.isDebugEnabled()) {
                        log.debug(
                                "OTLP exporter: " + spanExporter + " is configured at "
                                        + endPointURL + " without headers.");
                    }
                }
            }

            sdkTracerProvider = SdkTracerProvider.builder()
                    .addSpanProcessor(BatchSpanProcessor.builder(spanExporter).build())
                    .setResource(TelemetryUtil.getTracerProviderResource(serviceName))
                    .build();

            openTelemetry = OpenTelemetrySdk.builder()
                    .setTracerProvider(sdkTracerProvider).
                    setPropagators(ContextPropagators.create(W3CTraceContextPropagator.getInstance()))
                    .build();

            if (log.isDebugEnabled()) {
                log.debug("OpenTelemetry instance: " + openTelemetry + " is configured.");
            }
        } else {
            log.error("The OTLP endpoint URL is not configured properly. Hence, the OTLP tracer " +
                    "initialization failed.");
        }
    }

    @Override
    public OpenTelemetry getAPIMOpenTelemetry() {

        return openTelemetry;
    }

    @Override
    public Tracer getTelemetryTracer() {

        return openTelemetry.getTracer(TelemetryConstants.OPENTELEMETRY_INSTRUMENTATION_NAME);
    }

    @Override
    public String getName() {

        return NAME;
    }

    @Override
    public void close() {

        if (sdkTracerProvider != null) {
            sdkTracerProvider.close();
        }
    }

    /**
     * Return the header key from properties file for specific OTLP based APM.
     *
     * @return Header key.
     */
    public String getHeaderKeyProperty() {

        Set<String> keySet = configuration.getConfigKeySet();
        for (String property : keySet) {
            if (property.startsWith(TelemetryConstants.OPENTELEMETRY_PROPERTIES_PREFIX)) {
                return property;
            }
        }
        return null;
    }

}
