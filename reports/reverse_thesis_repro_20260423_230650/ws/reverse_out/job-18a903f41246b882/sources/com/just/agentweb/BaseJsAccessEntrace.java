package com.just.agentweb;

import android.os.Build;
import android.webkit.ValueCallback;
import android.webkit.WebView;
import com.litesuits.orm.db.assit.SQLBuilder;

/* JADX INFO: loaded from: classes3.dex */
public abstract class BaseJsAccessEntrace implements JsAccessEntrace {
    public static final String TAG = BaseJsAccessEntrace.class.getSimpleName();
    private WebView mWebView;

    BaseJsAccessEntrace(WebView webView) {
        this.mWebView = webView;
    }

    @Override // com.just.agentweb.JsAccessEntrace
    public void callJs(String js, ValueCallback<String> callback) {
        if (Build.VERSION.SDK_INT >= 19) {
            evaluateJs(js, callback);
        } else {
            loadJs(js);
        }
    }

    @Override // com.just.agentweb.JsAccessEntrace
    public void callJs(String js) {
        callJs(js, null);
    }

    private void loadJs(String js) {
        this.mWebView.loadUrl(js);
    }

    private void evaluateJs(String js, final ValueCallback<String> callback) {
        this.mWebView.evaluateJavascript(js, new ValueCallback<String>() { // from class: com.just.agentweb.BaseJsAccessEntrace.1
            @Override // android.webkit.ValueCallback
            public void onReceiveValue(String value) {
                ValueCallback valueCallback = callback;
                if (valueCallback != null) {
                    valueCallback.onReceiveValue(value);
                }
            }
        });
    }

    @Override // com.just.agentweb.QuickCallJs
    public void quickCallJs(String method, ValueCallback<String> callback, String... params) {
        StringBuilder sb = new StringBuilder();
        sb.append("javascript:" + method);
        if (params == null || params.length == 0) {
            sb.append("()");
        } else {
            sb.append(SQLBuilder.PARENTHESES_LEFT);
            sb.append(concat(params));
            sb.append(SQLBuilder.PARENTHESES_RIGHT);
        }
        callJs(sb.toString(), callback);
    }

    private String concat(String... params) {
        StringBuilder mStringBuilder = new StringBuilder();
        for (int i = 0; i < params.length; i++) {
            String param = params[i];
            if (!AgentWebUtils.isJson(param)) {
                mStringBuilder.append("\"");
                mStringBuilder.append(param);
                mStringBuilder.append("\"");
            } else {
                mStringBuilder.append(param);
            }
            if (i != params.length - 1) {
                mStringBuilder.append(" , ");
            }
        }
        return mStringBuilder.toString();
    }

    @Override // com.just.agentweb.QuickCallJs
    public void quickCallJs(String method, String... params) {
        quickCallJs(method, null, params);
    }

    @Override // com.just.agentweb.QuickCallJs
    public void quickCallJs(String method) {
        quickCallJs(method, (String[]) null);
    }
}
