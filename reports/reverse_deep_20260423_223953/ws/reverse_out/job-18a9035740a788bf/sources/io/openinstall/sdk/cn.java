package io.openinstall.sdk;

import java.util.HashMap;
import java.util.Map;

/* JADX INFO: loaded from: classes3.dex */
public class cn implements cm {
    private static final String b = dw.a("VXNlci1BZ2VudA");
    private static final String c = dw.a("T3Blbkluc3RhbGxTREs");
    public final String a;

    public cn(String str) {
        this.a = str;
    }

    @Override // io.openinstall.sdk.cm
    public cl a() {
        return cl.GET;
    }

    @Override // io.openinstall.sdk.cm
    public String b() {
        return this.a;
    }

    @Override // io.openinstall.sdk.cm
    public String c() {
        return "t=" + System.currentTimeMillis();
    }

    @Override // io.openinstall.sdk.cm
    public byte[] d() {
        return null;
    }

    @Override // io.openinstall.sdk.cm
    public Map<String, String> e() {
        HashMap map = new HashMap();
        map.put(b, c);
        return map;
    }
}
