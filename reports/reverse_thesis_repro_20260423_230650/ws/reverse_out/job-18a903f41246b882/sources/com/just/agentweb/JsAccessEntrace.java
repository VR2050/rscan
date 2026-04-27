package com.just.agentweb;

import android.webkit.ValueCallback;

/* JADX INFO: loaded from: classes3.dex */
public interface JsAccessEntrace extends QuickCallJs {
    void callJs(String str);

    void callJs(String str, ValueCallback<String> valueCallback);
}
