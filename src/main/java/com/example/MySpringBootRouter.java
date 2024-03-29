package com.example;

import org.apache.camel.builder.RouteBuilder;
import org.apache.camel.http.base.HttpOperationFailedException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

import java.net.URLEncoder;

import org.apache.camel.Exchange;
import org.apache.camel.Processor;
import org.apache.camel.Message;

/**
 * A simple Camel route that triggers from a timer and calls a bean and prints to system out.
 * <p/>
 * Use <tt>@Component</tt> to make Camel auto detect this route when starting.
 */
@Component
public class MySpringBootRouter extends RouteBuilder {
	
	@Autowired
	private Environment env;

    @Override
    public void configure() throws Exception {
    	
    	String erpUri = "https://5298967-sb1.restlets.api.netsuite.com/app/site/hosting/restlet.nl?script=583&deploy=1";
    	
    	onException(HttpOperationFailedException.class)
			.handled(true)
			.process(exchange -> {
				System.out.println("No hay registros en el periodo de consulta");
				System.out.println(exchange.getProperties());
			});
			//.continued(true); // Para continuar con la ruta

    	
    	from("timer:poll?period={{timer.period}}").routeId("{{route.id}}")
    		.process(exchange -> {
				System.out.println("******** Inicia Peticion ********:");
    			String wmsUri = env.getProperty("wms.uri");
				System.out.println("URL WMS: " + wmsUri);
    			// String dateRange = WmsParams.getDateRange(60 * 60 * 24 * 90); // Poll interval in seconds (3 months)
    			// String dateRange = WmsParams.getDateRange(30); // Poll interval in seconds (30 seconds)
    			String dateRange = WmsParams.getDateRange(60 * 60); // Poll interval in seconds (1 hour)
    			System.out.println();
    			System.out.println();
    			System.out.println("Periodo de consulta: " + dateRange);
    			String encodedDateRange = URLEncoder.encode(dateRange, "UTF-8");
    	    	exchange.getMessage().setHeader(Exchange.HTTP_QUERY, "warehouse=28002&between=" + encodedDateRange);
    	    	exchange.getMessage().setHeader(Exchange.HTTP_URI, wmsUri);
    		})
    		.to("log:DEBUG?showBody=true&showHeaders=true")
    		//.to("https://test?throwExceptionOnFailure=false") // Para no lanzar errores
    		.to("https://wms")
        	.to("log:DEBUG?showBody=true&showHeaders=true")
        	.removeHeaders("*")
        	.setHeader("CamelHttpMethod", constant("POST"))
        	.setHeader(Exchange.HTTP_URI, constant(erpUri))
        	.process(new Processor() {
                @Override
                public void process(Exchange exchange) throws Exception {
                	String authHeader = OAuthSign.getAuthHeader(erpUri);
                    exchange.getMessage().setHeader("Authorization", authHeader);
                }
        	})
        	.setHeader(Exchange.CONTENT_TYPE, constant("application/json"))
        	.to("log:DEBUG?showBody=true&showHeaders=true")
        	.to("https://netsuite")
        	.to("log:DEBUG?showBody=true&showHeaders=true")
			.streamCaching()
			.process(new Processor() {
				@Override
				public void process(Exchange exchange) throws Exception {
				Message message = exchange.getMessage();
				String body = message.getBody(String.class);
				System.out.println("Response:"+ body);
				System.out.println("********Fin de la Peticion********");
				}
			});
        	//.to("stream:out");
    }

}
