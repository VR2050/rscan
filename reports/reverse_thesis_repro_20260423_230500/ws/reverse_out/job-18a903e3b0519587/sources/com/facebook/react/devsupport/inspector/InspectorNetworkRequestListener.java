package com.facebook.react.devsupport.inspector;

import com.facebook.jni.HybridData;
import java.util.Map;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public final class InspectorNetworkRequestListener {
    private final HybridData mHybridData;

    public InspectorNetworkRequestListener(HybridData hybridData) {
        j.f(hybridData, "mHybridData");
        this.mHybridData = hybridData;
    }

    public final native void onCompletion();

    public final native void onData(String str);

    public final native void onError(String str);

    public final native void onHeaders(int i3, Map<String, String> map);
}
