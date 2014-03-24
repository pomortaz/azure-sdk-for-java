/**
 * 
 * Copyright (c) Microsoft and contributors.  All rights reserved.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *   http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * 
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 */

// Warning: This code was generated by a tool.
// 
// Changes to this file may cause incorrect behavior and will be lost if the
// code is regenerated.

package com.microsoft.windowsazure.management.websites;

import com.microsoft.windowsazure.core.OperationResponse;
import com.microsoft.windowsazure.exception.ServiceException;
import com.microsoft.windowsazure.management.websites.models.ServerFarmCreateParameters;
import com.microsoft.windowsazure.management.websites.models.ServerFarmCreateResponse;
import com.microsoft.windowsazure.management.websites.models.ServerFarmGetResponse;
import com.microsoft.windowsazure.management.websites.models.ServerFarmListResponse;
import com.microsoft.windowsazure.management.websites.models.ServerFarmUpdateParameters;
import com.microsoft.windowsazure.management.websites.models.ServerFarmUpdateResponse;
import java.io.IOException;
import java.net.URISyntaxException;
import java.util.concurrent.Future;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerException;
import org.xml.sax.SAXException;

/**
* Operations for managing the server farm in a web space.  (see
* http://msdn.microsoft.com/en-us/library/windowsazure/dn194277.aspx for more
* information)
*/
public interface ServerFarmOperations {
    /**
    * You can create a server farm by issuing an HTTP POST request. Only one
    * server farm per webspace is permitted. You can retrieve server farm
    * details by using HTTP GET, change server farm properties by using HTTP
    * PUT, and delete a server farm by using HTTP DELETE. A request body is
    * required for server farm creation (HTTP POST) and server farm update
    * (HTTP PUT).  Warning: Creating a server farm changes your webspace’s
    * Compute Mode from Shared to Dedicated. You will be charged from the
    * moment the server farm is created, even if all your sites are still
    * running in Free mode.  (see
    * http://msdn.microsoft.com/en-us/library/windowsazure/dn194277.aspx for
    * more information)
    *
    * @param webSpaceName Required. The name of the web space.
    * @param parameters Required. Parameters supplied to the Create Server Farm
    * operation.
    * @throws ParserConfigurationException Thrown if there was an error
    * configuring the parser for the response body.
    * @throws SAXException Thrown if there was an error parsing the response
    * body.
    * @throws TransformerException Thrown if there was an error creating the
    * DOM transformer.
    * @throws IOException Signals that an I/O exception of some sort has
    * occurred. This class is the general class of exceptions produced by
    * failed or interrupted I/O operations.
    * @throws ServiceException Thrown if an unexpected response is found.
    * @throws URISyntaxException Thrown if there was an error parsing a URI in
    * the response.
    * @return The Create Server Farm operation response.
    */
    ServerFarmCreateResponse create(String webSpaceName, ServerFarmCreateParameters parameters) throws ParserConfigurationException, SAXException, TransformerException, IOException, ServiceException, URISyntaxException;
    
    /**
    * You can create a server farm by issuing an HTTP POST request. Only one
    * server farm per webspace is permitted. You can retrieve server farm
    * details by using HTTP GET, change server farm properties by using HTTP
    * PUT, and delete a server farm by using HTTP DELETE. A request body is
    * required for server farm creation (HTTP POST) and server farm update
    * (HTTP PUT).  Warning: Creating a server farm changes your webspace’s
    * Compute Mode from Shared to Dedicated. You will be charged from the
    * moment the server farm is created, even if all your sites are still
    * running in Free mode.  (see
    * http://msdn.microsoft.com/en-us/library/windowsazure/dn194277.aspx for
    * more information)
    *
    * @param webSpaceName Required. The name of the web space.
    * @param parameters Required. Parameters supplied to the Create Server Farm
    * operation.
    * @return The Create Server Farm operation response.
    */
    Future<ServerFarmCreateResponse> createAsync(String webSpaceName, ServerFarmCreateParameters parameters);
    
    /**
    * You can create a server farm by issuing an HTTP POST request. Only one
    * server farm per webspace is permitted. You can retrieve server farm
    * details by using HTTP GET, change server farm properties by using HTTP
    * PUT, and delete a server farm by using HTTP DELETE. A request body is
    * required for server farm creation (HTTP POST) and server farm update
    * (HTTP PUT).  Warning: Creating a server farm changes your webspace’s
    * Compute Mode from Shared to Dedicated. You will be charged from the
    * moment the server farm is created, even if all your sites are still
    * running in Free mode.  (see
    * http://msdn.microsoft.com/en-us/library/windowsazure/dn194277.aspx for
    * more information)
    *
    * @param webSpaceName Required. The name of the web space.
    * @throws IOException Signals that an I/O exception of some sort has
    * occurred. This class is the general class of exceptions produced by
    * failed or interrupted I/O operations.
    * @throws ServiceException Thrown if an unexpected response is found.
    * @return A standard service response including an HTTP status code and
    * request ID.
    */
    OperationResponse delete(String webSpaceName) throws IOException, ServiceException;
    
    /**
    * You can create a server farm by issuing an HTTP POST request. Only one
    * server farm per webspace is permitted. You can retrieve server farm
    * details by using HTTP GET, change server farm properties by using HTTP
    * PUT, and delete a server farm by using HTTP DELETE. A request body is
    * required for server farm creation (HTTP POST) and server farm update
    * (HTTP PUT).  Warning: Creating a server farm changes your webspace’s
    * Compute Mode from Shared to Dedicated. You will be charged from the
    * moment the server farm is created, even if all your sites are still
    * running in Free mode.  (see
    * http://msdn.microsoft.com/en-us/library/windowsazure/dn194277.aspx for
    * more information)
    *
    * @param webSpaceName Required. The name of the web space.
    * @return A standard service response including an HTTP status code and
    * request ID.
    */
    Future<OperationResponse> deleteAsync(String webSpaceName);
    
    /**
    * You can create a server farm by issuing an HTTP POST request. Only one
    * server farm per webspace is permitted. You can retrieve server farm
    * details by using HTTP GET, change server farm properties by using HTTP
    * PUT, and delete a server farm by using HTTP DELETE. A request body is
    * required for server farm creation (HTTP POST) and server farm update
    * (HTTP PUT).  Warning: Creating a server farm changes your webspace’s
    * Compute Mode from Shared to Dedicated. You will be charged from the
    * moment the server farm is created, even if all your sites are still
    * running in Free mode.  (see
    * http://msdn.microsoft.com/en-us/library/windowsazure/dn194277.aspx for
    * more information)
    *
    * @param webSpaceName Required. The name of the web space.
    * @param serverFarmName Required. The name of the server farm.
    * @throws IOException Signals that an I/O exception of some sort has
    * occurred. This class is the general class of exceptions produced by
    * failed or interrupted I/O operations.
    * @throws ServiceException Thrown if an unexpected response is found.
    * @throws ParserConfigurationException Thrown if there was a serious
    * configuration error with the document parser.
    * @throws SAXException Thrown if there was an error parsing the XML
    * response.
    * @throws URISyntaxException Thrown if there was an error parsing a URI in
    * the response.
    * @return The Get Server Farm operation response.
    */
    ServerFarmGetResponse get(String webSpaceName, String serverFarmName) throws IOException, ServiceException, ParserConfigurationException, SAXException, URISyntaxException;
    
    /**
    * You can create a server farm by issuing an HTTP POST request. Only one
    * server farm per webspace is permitted. You can retrieve server farm
    * details by using HTTP GET, change server farm properties by using HTTP
    * PUT, and delete a server farm by using HTTP DELETE. A request body is
    * required for server farm creation (HTTP POST) and server farm update
    * (HTTP PUT).  Warning: Creating a server farm changes your webspace’s
    * Compute Mode from Shared to Dedicated. You will be charged from the
    * moment the server farm is created, even if all your sites are still
    * running in Free mode.  (see
    * http://msdn.microsoft.com/en-us/library/windowsazure/dn194277.aspx for
    * more information)
    *
    * @param webSpaceName Required. The name of the web space.
    * @param serverFarmName Required. The name of the server farm.
    * @return The Get Server Farm operation response.
    */
    Future<ServerFarmGetResponse> getAsync(String webSpaceName, String serverFarmName);
    
    /**
    * You can create a server farm by issuing an HTTP POST request. Only one
    * server farm per webspace is permitted. You can retrieve server farm
    * details by using HTTP GET, change server farm properties by using HTTP
    * PUT, and delete a server farm by using HTTP DELETE. A request body is
    * required for server farm creation (HTTP POST) and server farm update
    * (HTTP PUT).  Warning: Creating a server farm changes your webspace’s
    * Compute Mode from Shared to Dedicated. You will be charged from the
    * moment the server farm is created, even if all your sites are still
    * running in Free mode.  (see
    * http://msdn.microsoft.com/en-us/library/windowsazure/dn194277.aspx for
    * more information)
    *
    * @param webSpaceName Required. The name of the web space.
    * @throws IOException Signals that an I/O exception of some sort has
    * occurred. This class is the general class of exceptions produced by
    * failed or interrupted I/O operations.
    * @throws ServiceException Thrown if an unexpected response is found.
    * @throws ParserConfigurationException Thrown if there was a serious
    * configuration error with the document parser.
    * @throws SAXException Thrown if there was an error parsing the XML
    * response.
    * @return The List Server Farm operation response.
    */
    ServerFarmListResponse list(String webSpaceName) throws IOException, ServiceException, ParserConfigurationException, SAXException;
    
    /**
    * You can create a server farm by issuing an HTTP POST request. Only one
    * server farm per webspace is permitted. You can retrieve server farm
    * details by using HTTP GET, change server farm properties by using HTTP
    * PUT, and delete a server farm by using HTTP DELETE. A request body is
    * required for server farm creation (HTTP POST) and server farm update
    * (HTTP PUT).  Warning: Creating a server farm changes your webspace’s
    * Compute Mode from Shared to Dedicated. You will be charged from the
    * moment the server farm is created, even if all your sites are still
    * running in Free mode.  (see
    * http://msdn.microsoft.com/en-us/library/windowsazure/dn194277.aspx for
    * more information)
    *
    * @param webSpaceName Required. The name of the web space.
    * @return The List Server Farm operation response.
    */
    Future<ServerFarmListResponse> listAsync(String webSpaceName);
    
    /**
    * You can create a server farm by issuing an HTTP POST request. Only one
    * server farm per webspace is permitted. You can retrieve server farm
    * details by using HTTP GET, change server farm properties by using HTTP
    * PUT, and delete a server farm by using HTTP DELETE. A request body is
    * required for server farm creation (HTTP POST) and server farm update
    * (HTTP PUT).  Warning: Creating a server farm changes your webspace’s
    * Compute Mode from Shared to Dedicated. You will be charged from the
    * moment the server farm is created, even if all your sites are still
    * running in Free mode.  (see
    * http://msdn.microsoft.com/en-us/library/windowsazure/dn194277.aspx for
    * more information)
    *
    * @param webSpaceName Required. The name of the web space.
    * @param parameters Required. Parameters supplied to the Update Server Farm
    * operation.
    * @throws ParserConfigurationException Thrown if there was an error
    * configuring the parser for the response body.
    * @throws SAXException Thrown if there was an error parsing the response
    * body.
    * @throws TransformerException Thrown if there was an error creating the
    * DOM transformer.
    * @throws IOException Signals that an I/O exception of some sort has
    * occurred. This class is the general class of exceptions produced by
    * failed or interrupted I/O operations.
    * @throws ServiceException Thrown if an unexpected response is found.
    * @throws URISyntaxException Thrown if there was an error parsing a URI in
    * the response.
    * @return The Update Server Farm operation response.
    */
    ServerFarmUpdateResponse update(String webSpaceName, ServerFarmUpdateParameters parameters) throws ParserConfigurationException, SAXException, TransformerException, IOException, ServiceException, URISyntaxException;
    
    /**
    * You can create a server farm by issuing an HTTP POST request. Only one
    * server farm per webspace is permitted. You can retrieve server farm
    * details by using HTTP GET, change server farm properties by using HTTP
    * PUT, and delete a server farm by using HTTP DELETE. A request body is
    * required for server farm creation (HTTP POST) and server farm update
    * (HTTP PUT).  Warning: Creating a server farm changes your webspace’s
    * Compute Mode from Shared to Dedicated. You will be charged from the
    * moment the server farm is created, even if all your sites are still
    * running in Free mode.  (see
    * http://msdn.microsoft.com/en-us/library/windowsazure/dn194277.aspx for
    * more information)
    *
    * @param webSpaceName Required. The name of the web space.
    * @param parameters Required. Parameters supplied to the Update Server Farm
    * operation.
    * @return The Update Server Farm operation response.
    */
    Future<ServerFarmUpdateResponse> updateAsync(String webSpaceName, ServerFarmUpdateParameters parameters);
}
