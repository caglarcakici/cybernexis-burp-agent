/*
 * Shared state passed to every tool executor: the Burp API, the message index,
 * scan tasks started this session, and a lazily-created Collaborator client.
 */
package com.cybernexis.agent.tools;

import java.util.LinkedHashMap;
import java.util.Map;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.collaborator.CollaboratorClient;
import burp.api.montoya.scanner.ScanTask;

public class ToolContext {

    public final MontoyaApi api;
    public final MessageStore messages;
    public final TargetMemory memory;

    private final Map<String, ScanTask> scanTasks = new LinkedHashMap<>();
    private int nextTaskId = 1;
    private CollaboratorClient collaboratorClient;

    // Phase 3 state
    private final Map<String, String> scripts = new LinkedHashMap<>();
    private final java.util.List<Map<String, Object>> importedChecks = new java.util.ArrayList<>();
    private Object lastScriptResult;
    private int nextCheckId = 1;

    /** Per-turn task focus so concurrent sessions do not clobber each other. */
    private final ThreadLocal<String> focusHost = new ThreadLocal<>();
    private final ThreadLocal<VarStore> vars = new ThreadLocal<>();
    private static final VarStore EMPTY_VARS = new VarStore();

    public ToolContext(MontoyaApi api, MessageStore messages) {
        this(api, messages, new TargetMemory());
    }

    public ToolContext(MontoyaApi api, MessageStore messages, TargetMemory memory) {
        this.api = api;
        this.messages = messages;
        this.memory = memory == null ? new TargetMemory() : memory;
    }

    public TargetMemory memory() {
        return memory;
    }

    public synchronized String registerScanTask(ScanTask task) {
        String id = "task-" + (nextTaskId++);
        scanTasks.put(id, task);
        return id;
    }

    public synchronized ScanTask scanTask(String id) {
        return scanTasks.get(id);
    }

    public synchronized Map<String, ScanTask> scanTasks() {
        return new LinkedHashMap<>(scanTasks);
    }

    /** Create the Collaborator client on first use so payloads share one context. */
    public synchronized CollaboratorClient collaborator() {
        if (collaboratorClient == null) {
            collaboratorClient = api.collaborator().createClient();
        }
        return collaboratorClient;
    }

    public synchronized boolean hasCollaborator() {
        return collaboratorClient != null;
    }

    // ---- Phase 3 state accessors -------------------------------------------

    public synchronized void putScript(String name, String source) {
        scripts.put(name, source);
    }

    public synchronized String getScript(String name) {
        return scripts.get(name);
    }

    public synchronized void setLastScriptResult(Object result) {
        this.lastScriptResult = result;
    }

    public synchronized Object getLastScriptResult() {
        return lastScriptResult;
    }

    public synchronized String registerImportedCheck(Map<String, Object> info) {
        String id = "check-" + (nextCheckId++);
        info.put("check_id", id);
        importedChecks.add(info);
        return id;
    }

    public synchronized java.util.List<Map<String, Object>> importedChecks() {
        return new java.util.ArrayList<>(importedChecks);
    }

    public void beginFocus(String host) {
        beginTurn(host, null);
    }

    public void beginTurn(String host, VarStore sessionVars) {
        String n = Focus.normalize(host);
        if (n == null) {
            focusHost.remove();
        } else {
            focusHost.set(n);
        }
        if (sessionVars != null) {
            vars.set(sessionVars);
        } else {
            vars.remove();
        }
    }

    public void endFocus() {
        endTurn();
    }

    public void endTurn() {
        focusHost.remove();
        vars.remove();
    }

    /** Host this task is locked to, or null if the task is project-wide. */
    public String focusHost() {
        return focusHost.get();
    }

    /** Variables for the in-flight agent turn; empty store if none is bound. */
    public VarStore vars() {
        VarStore v = vars.get();
        return v != null ? v : EMPTY_VARS;
    }
}
