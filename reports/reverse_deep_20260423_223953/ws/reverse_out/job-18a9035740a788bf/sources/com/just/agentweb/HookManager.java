package com.just.agentweb;

import com.just.agentweb.AgentWeb;

/* JADX INFO: loaded from: classes3.dex */
public class HookManager {
    public static AgentWeb hookAgentWeb(AgentWeb agentWeb, AgentWeb.AgentBuilder agentBuilder) {
        return agentWeb;
    }

    public static boolean permissionHook(String url, String[] permissions) {
        return true;
    }
}
