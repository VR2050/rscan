package com.facebook.react.fabric;

import c2.C0353a;
import com.facebook.react.bridge.ReactMarker;
import com.facebook.react.bridge.ReactMarkerConstants;
import com.facebook.soloader.SoLoader;

/* JADX INFO: loaded from: classes.dex */
public final class c {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    public static final c f6951a = new c();

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private static volatile boolean f6952b;

    private c() {
    }

    public static final void a() {
        if (f6952b) {
            return;
        }
        C0353a.c(0L, "FabricSoLoader.staticInit::load:fabricjni");
        ReactMarker.logMarker(ReactMarkerConstants.LOAD_REACT_NATIVE_SO_FILE_START);
        SoLoader.t("fabricjni");
        ReactMarker.logMarker(ReactMarkerConstants.LOAD_REACT_NATIVE_SO_FILE_END);
        C0353a.i(0L);
        f6952b = true;
    }
}
