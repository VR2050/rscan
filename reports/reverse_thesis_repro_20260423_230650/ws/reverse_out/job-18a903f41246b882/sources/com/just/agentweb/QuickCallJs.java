package com.just.agentweb;

import android.webkit.ValueCallback;

/* JADX INFO: loaded from: classes3.dex */
public interface QuickCallJs {
    void quickCallJs(String str);

    void quickCallJs(String str, ValueCallback<String> valueCallback, String... strArr);

    void quickCallJs(String str, String... strArr);
}
