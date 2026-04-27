package com.facebook.react.modules.blob;

import com.facebook.react.bridge.JavaScriptContextHolder;
import com.facebook.react.bridge.ReactContext;
import com.facebook.react.modules.blob.BlobCollector;
import com.facebook.soloader.SoLoader;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public final class BlobCollector {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    public static final BlobCollector f7010a = new BlobCollector();

    static {
        SoLoader.t("reactnativeblob");
    }

    private BlobCollector() {
    }

    public static final void b(final ReactContext reactContext, final BlobModule blobModule) {
        j.f(reactContext, "reactContext");
        j.f(blobModule, "blobModule");
        reactContext.runOnJSQueueThread(new Runnable() { // from class: y1.a
            @Override // java.lang.Runnable
            public final void run() {
                BlobCollector.c(reactContext, blobModule);
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final void c(ReactContext reactContext, BlobModule blobModule) {
        JavaScriptContextHolder javaScriptContextHolder = reactContext.getJavaScriptContextHolder();
        if (javaScriptContextHolder == null || javaScriptContextHolder.get() == 0) {
            return;
        }
        f7010a.nativeInstall(blobModule, javaScriptContextHolder.get());
    }

    private final native void nativeInstall(Object obj, long j3);
}
