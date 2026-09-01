/*
 * Contract for a user-provided Montoya script. The model supplies the body of
 * run(); it has access to the live MontoyaApi and returns any value to report.
 */
package com.cybernexis.agent.script;

import burp.api.montoya.MontoyaApi;

public interface UserScript {
    Object run(MontoyaApi api) throws Exception;
}
