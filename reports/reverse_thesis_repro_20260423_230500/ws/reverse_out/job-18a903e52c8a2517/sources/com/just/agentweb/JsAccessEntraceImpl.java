package com.just.agentweb;

import android.os.Handler;
import android.os.Looper;
import android.webkit.ValueCallback;
import android.webkit.WebView;

/* JADX INFO: loaded from: classes3.dex */
public class JsAccessEntraceImpl extends BaseJsAccessEntrace {
    private Handler mHandler;
    private WebView mWebView;

    public static JsAccessEntraceImpl getInstance(WebView webView) {
        return new JsAccessEntraceImpl(webView);
    }

    private JsAccessEntraceImpl(WebView webView) {
        super(webView);
        this.mHandler = new Handler(Looper.getMainLooper());
        this.mWebView = webView;
    }

    private void safeCallJs(final String s, final ValueCallback valueCallback) {
        this.mHandler.post(new Runnable() { // from class: com.just.agentweb.JsAccessEntraceImpl.1
            @Override // java.lang.Runnable
            public void run() {
                JsAccessEntraceImpl.this.callJs(s, valueCallback);
            }
        });
    }

    @Override // com.just.agentweb.BaseJsAccessEntrace, com.just.agentweb.JsAccessEntrace
    public void callJs(String params, ValueCallback<String> callback) {
        if (Thread.currentThread() != Looper.getMainLooper().getThread()) {
            safeCallJs(params, callback);
        } else {
            super.callJs(params, callback);
        }
    }
}
