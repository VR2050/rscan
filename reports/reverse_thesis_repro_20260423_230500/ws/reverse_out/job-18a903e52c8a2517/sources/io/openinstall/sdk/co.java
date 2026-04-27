package io.openinstall.sdk;

import java.util.HashMap;
import java.util.Map;

/* JADX INFO: loaded from: classes3.dex */
public class co extends cp {
    private String a;

    public co(boolean z, String str) {
        super(z, str);
    }

    public void a(String str) {
        this.a = str;
    }

    @Override // io.openinstall.sdk.cp, io.openinstall.sdk.cm
    public byte[] d() {
        String str = this.a;
        if (str == null || str.length() <= 0) {
            return null;
        }
        return this.a.getBytes(bu.c);
    }

    @Override // io.openinstall.sdk.cp, io.openinstall.sdk.cm
    public Map<String, String> e() {
        if (d() == null || d().length == 0) {
            return super.e();
        }
        HashMap map = new HashMap();
        map.put("content-type", "text/plain;charset=utf-8");
        map.put("content-length", String.valueOf(d().length));
        return map;
    }
}
