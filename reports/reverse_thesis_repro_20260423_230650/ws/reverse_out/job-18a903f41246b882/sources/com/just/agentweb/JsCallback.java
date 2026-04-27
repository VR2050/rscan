package com.just.agentweb;

import android.util.Log;
import android.webkit.WebView;
import java.lang.ref.WeakReference;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* JADX INFO: loaded from: classes3.dex */
public class JsCallback {
    private static final String CALLBACK_JS_FORMAT = "javascript:%s.callback(%d, %d %s);";
    private boolean mCouldGoOn = true;
    private int mIndex;
    private String mInjectedName;
    private int mIsPermanent;
    private WeakReference<WebView> mWebViewRef;

    public JsCallback(WebView view, String injectedName, int index) {
        this.mWebViewRef = new WeakReference<>(view);
        this.mInjectedName = injectedName;
        this.mIndex = index;
    }

    public void apply(Object... args) throws JsCallbackException {
        if (this.mWebViewRef.get() == null) {
            throw new JsCallbackException("the WebView related to the JsCallback has been recycled");
        }
        if (!this.mCouldGoOn) {
            throw new JsCallbackException("the JsCallback isn't permanent,cannot be called more than once");
        }
        StringBuilder sb = new StringBuilder();
        for (Object arg : args) {
            sb.append(",");
            boolean isStrArg = arg instanceof String;
            boolean isObjArg = isJavaScriptObject(arg);
            if (isStrArg && !isObjArg) {
                sb.append("\"");
            }
            sb.append(String.valueOf(arg));
            if (isStrArg && !isObjArg) {
                sb.append("\"");
            }
        }
        String execJs = String.format(CALLBACK_JS_FORMAT, this.mInjectedName, Integer.valueOf(this.mIndex), Integer.valueOf(this.mIsPermanent), sb.toString());
        if (LogUtils.isDebug()) {
            Log.d("JsCallBack", execJs);
        }
        this.mWebViewRef.get().loadUrl(execJs);
        this.mCouldGoOn = this.mIsPermanent > 0;
    }

    private boolean isJavaScriptObject(Object obj) {
        if ((obj instanceof JSONObject) || (obj instanceof JSONArray)) {
            return true;
        }
        String json = obj.toString();
        try {
            new JSONObject(json);
        } catch (JSONException e) {
            try {
                new JSONArray(json);
            } catch (JSONException e2) {
                return false;
            }
        }
        return true;
    }

    public void setPermanent(boolean z) {
        this.mIsPermanent = z ? 1 : 0;
    }

    public static class JsCallbackException extends Exception {
        public JsCallbackException(String msg) {
            super(msg);
        }
    }
}
