package io.openinstall.sdk;

import java.util.HashMap;
import java.util.Map;

/* JADX INFO: loaded from: classes3.dex */
public abstract class ci implements au<Map<String, String>> {
    protected final ay a;
    protected final as b = as.a();

    protected ci(ay ayVar) {
        this.a = ayVar;
    }

    protected abstract Map<String, String> a();

    @Override // io.openinstall.sdk.au
    /* JADX INFO: renamed from: c, reason: merged with bridge method [inline-methods] */
    public Map<String, String> a_() {
        HashMap map = new HashMap();
        map.put("jpaw", this.a.d());
        map.put("opof", this.a.c());
        map.put("kjfe", this.a.e());
        map.put("hwef", String.valueOf(this.a.f()));
        map.put("vsna", this.a.g());
        map.putAll(a());
        return map;
    }
}
