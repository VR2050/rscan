package com.just.agentweb;

import android.content.Context;
import android.graphics.Bitmap;
import android.os.Build;
import android.util.AttributeSet;
import android.util.Log;
import android.util.Pair;
import android.view.ViewGroup;
import android.view.ViewParent;
import android.view.accessibility.AccessibilityManager;
import android.webkit.JsPromptResult;
import android.webkit.WebBackForwardList;
import android.webkit.WebView;
import android.widget.Toast;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.URI;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Map;
import org.json.JSONObject;

/* JADX INFO: loaded from: classes3.dex */
public class AgentWebView extends LollipopFixedWebView {
    private static final String TAG = AgentWebView.class.getSimpleName();
    private FixedOnReceivedTitle mFixedOnReceivedTitle;
    private Map<String, String> mInjectJavaScripts;
    private Boolean mIsAccessibilityEnabledOriginal;
    private boolean mIsInited;
    private Map<String, JsCallJava> mJsCallJavas;

    public AgentWebView(Context context) {
        this(context, null);
    }

    public AgentWebView(Context context, AttributeSet attrs) {
        super(context, attrs);
        removeSearchBoxJavaBridge();
        this.mIsInited = true;
        this.mFixedOnReceivedTitle = new FixedOnReceivedTitle();
    }

    @Override // android.webkit.WebView
    @Deprecated
    public final void addJavascriptInterface(Object interfaceObj, String interfaceName) {
        if (Build.VERSION.SDK_INT >= 17) {
            super.addJavascriptInterface(interfaceObj, interfaceName);
            Log.i(TAG, "注入");
            return;
        }
        Log.i(TAG, "use mJsCallJavas:" + interfaceName);
        LogUtils.i(TAG, "addJavascriptInterface:" + interfaceObj + "   interfaceName:" + interfaceName);
        if (this.mJsCallJavas == null) {
            this.mJsCallJavas = new HashMap();
        }
        this.mJsCallJavas.put(interfaceName, new JsCallJava(interfaceObj, interfaceName));
        injectJavaScript();
        if (LogUtils.isDebug()) {
            Log.d(TAG, "injectJavaScript, addJavascriptInterface.interfaceObj = " + interfaceObj + ", interfaceName = " + interfaceName);
        }
        addJavascriptInterfaceSupport(interfaceObj, interfaceName);
    }

    protected void addJavascriptInterfaceSupport(Object interfaceObj, String interfaceName) {
    }

    @Override // android.webkit.WebView
    public final void setWebChromeClient(android.webkit.WebChromeClient client) {
        AgentWebChrome mAgentWebChrome = new AgentWebChrome();
        mAgentWebChrome.setDelegate(client);
        this.mFixedOnReceivedTitle.setWebChromeClient(client);
        super.setWebChromeClient(mAgentWebChrome);
        setWebChromeClientSupport(mAgentWebChrome);
    }

    protected final void setWebChromeClientSupport(android.webkit.WebChromeClient client) {
    }

    @Override // android.webkit.WebView
    public final void setWebViewClient(android.webkit.WebViewClient client) {
        AgentWebClient mAgentWebClient = new AgentWebClient();
        mAgentWebClient.setDelegate(client);
        super.setWebViewClient(mAgentWebClient);
        setWebViewClientSupport(mAgentWebClient);
    }

    public final void setWebViewClientSupport(android.webkit.WebViewClient client) {
    }

    @Override // android.webkit.WebView
    public void destroy() {
        setVisibility(8);
        Map<String, JsCallJava> map = this.mJsCallJavas;
        if (map != null) {
            map.clear();
        }
        Map<String, String> map2 = this.mInjectJavaScripts;
        if (map2 != null) {
            map2.clear();
        }
        removeAllViewsInLayout();
        fixedStillAttached();
        releaseConfigCallback();
        if (this.mIsInited) {
            resetAccessibilityEnabled();
            LogUtils.i(TAG, "destroy web");
            super.destroy();
        }
    }

    @Override // android.webkit.WebView
    public void clearHistory() {
        if (this.mIsInited) {
            super.clearHistory();
        }
    }

    public static Pair<Boolean, String> isWebViewPackageException(Throwable e) {
        String messageCause = e.getCause() == null ? e.toString() : e.getCause().toString();
        String trace = Log.getStackTraceString(e);
        if (trace.contains("android.content.pm.PackageManager$NameNotFoundException") || trace.contains("java.lang.RuntimeException: Cannot load WebView") || trace.contains("android.webkit.WebViewFactory$MissingWebViewPackageException: Failed to load WebView provider: No WebView installed")) {
            LogUtils.safeCheckCrash(TAG, "isWebViewPackageException", e);
            return new Pair<>(true, "WebView load failed, " + messageCause);
        }
        return new Pair<>(false, messageCause);
    }

    @Override // android.webkit.WebView, android.view.View
    public void setOverScrollMode(int mode) {
        try {
            super.setOverScrollMode(mode);
        } catch (Throwable e) {
            Pair<Boolean, String> pair = isWebViewPackageException(e);
            if (((Boolean) pair.first).booleanValue()) {
                Toast.makeText(getContext(), (CharSequence) pair.second, 0).show();
                destroy();
                return;
            }
            throw e;
        }
    }

    @Override // android.webkit.WebView
    public boolean isPrivateBrowsingEnabled() {
        if (Build.VERSION.SDK_INT == 15 && getSettings() == null) {
            return false;
        }
        return super.isPrivateBrowsingEnabled();
    }

    public void addInjectJavaScript(String javaScript) {
        if (this.mInjectJavaScripts == null) {
            this.mInjectJavaScripts = new HashMap();
        }
        this.mInjectJavaScripts.put(String.valueOf(javaScript.hashCode()), javaScript);
        injectExtraJavaScript();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void injectJavaScript() {
        for (Map.Entry<String, JsCallJava> entry : this.mJsCallJavas.entrySet()) {
            loadUrl(buildNotRepeatInjectJS(entry.getKey(), entry.getValue().getPreloadInterfaceJs()));
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void injectExtraJavaScript() {
        for (Map.Entry<String, String> entry : this.mInjectJavaScripts.entrySet()) {
            loadUrl(buildNotRepeatInjectJS(entry.getKey(), entry.getValue()));
        }
    }

    public String buildNotRepeatInjectJS(String key, String js) {
        String obj = String.format("__injectFlag_%1$s__", key);
        return "javascript:try{(function(){if(window." + obj + "){console.log('" + obj + " has been injected');return;}window." + obj + "=true;" + js + "}())}catch(e){console.warn(e)}";
    }

    public String buildTryCatchInjectJS(String js) {
        return "javascript:try{" + js + "}catch(e){console.warn(e)}";
    }

    public static class AgentWebClient extends MiddlewareWebClientBase {
        private AgentWebView mAgentWebView;

        private AgentWebClient(AgentWebView agentWebView) {
            this.mAgentWebView = agentWebView;
        }

        @Override // com.just.agentweb.WebViewClientDelegate, android.webkit.WebViewClient
        public void onPageStarted(WebView view, String url, Bitmap favicon) {
            super.onPageStarted(view, url, favicon);
            if (this.mAgentWebView.mJsCallJavas != null) {
                this.mAgentWebView.injectJavaScript();
                if (LogUtils.isDebug()) {
                    Log.d(AgentWebView.TAG, "injectJavaScript, onPageStarted.url = " + view.getUrl());
                }
            }
            if (this.mAgentWebView.mInjectJavaScripts != null) {
                this.mAgentWebView.injectExtraJavaScript();
            }
            this.mAgentWebView.mFixedOnReceivedTitle.onPageStarted();
            this.mAgentWebView.fixedAccessibilityInjectorExceptionForOnPageFinished(url);
        }

        @Override // com.just.agentweb.WebViewClientDelegate, android.webkit.WebViewClient
        public void onPageFinished(WebView view, String url) {
            super.onPageFinished(view, url);
            this.mAgentWebView.mFixedOnReceivedTitle.onPageFinished(view);
            if (LogUtils.isDebug()) {
                Log.d(AgentWebView.TAG, "onPageFinished.url = " + view.getUrl());
            }
        }
    }

    public static class AgentWebChrome extends MiddlewareWebChromeBase {
        private AgentWebView mAgentWebView;

        private AgentWebChrome(AgentWebView agentWebView) {
            this.mAgentWebView = agentWebView;
        }

        @Override // com.just.agentweb.WebChromeClientDelegate, android.webkit.WebChromeClient
        public void onReceivedTitle(WebView view, String title) {
            this.mAgentWebView.mFixedOnReceivedTitle.onReceivedTitle();
            super.onReceivedTitle(view, title);
        }

        @Override // com.just.agentweb.WebChromeClientDelegate, android.webkit.WebChromeClient
        public void onProgressChanged(WebView view, int newProgress) {
            if (this.mAgentWebView.mJsCallJavas != null) {
                this.mAgentWebView.injectJavaScript();
                if (LogUtils.isDebug()) {
                    Log.d(AgentWebView.TAG, "injectJavaScript, onProgressChanged.newProgress = " + newProgress + ", url = " + view.getUrl());
                }
            }
            if (this.mAgentWebView.mInjectJavaScripts != null) {
                this.mAgentWebView.injectExtraJavaScript();
            }
            super.onProgressChanged(view, newProgress);
        }

        @Override // com.just.agentweb.WebChromeClientDelegate, android.webkit.WebChromeClient
        public boolean onJsPrompt(WebView view, String url, String message, String defaultValue, JsPromptResult result) {
            JsCallJava mJsCallJava;
            Log.i(AgentWebView.TAG, "onJsPrompt:" + url + "  message:" + message + "  d:" + defaultValue + "  ");
            if (this.mAgentWebView.mJsCallJavas != null && JsCallJava.isSafeWebViewCallMsg(message)) {
                JSONObject jsonObject = JsCallJava.getMsgJSONObject(message);
                String interfacedName = JsCallJava.getInterfacedName(jsonObject);
                if (interfacedName != null && (mJsCallJava = (JsCallJava) this.mAgentWebView.mJsCallJavas.get(interfacedName)) != null) {
                    result.confirm(mJsCallJava.call(view, jsonObject));
                    return true;
                }
                return true;
            }
            return super.onJsPrompt(view, url, message, defaultValue, result);
        }
    }

    private static class FixedOnReceivedTitle {
        private boolean mIsOnReceivedTitle;
        private android.webkit.WebChromeClient mWebChromeClient;

        private FixedOnReceivedTitle() {
        }

        public void setWebChromeClient(android.webkit.WebChromeClient webChromeClient) {
            this.mWebChromeClient = webChromeClient;
        }

        public void onPageStarted() {
            this.mIsOnReceivedTitle = false;
        }

        public void onPageFinished(WebView view) {
            if (!this.mIsOnReceivedTitle && this.mWebChromeClient != null) {
                WebBackForwardList list = null;
                try {
                    list = view.copyBackForwardList();
                } catch (NullPointerException e) {
                    if (LogUtils.isDebug()) {
                        e.printStackTrace();
                    }
                }
                if (list != null && list.getSize() > 0 && list.getCurrentIndex() >= 0 && list.getItemAtIndex(list.getCurrentIndex()) != null) {
                    String previousTitle = list.getItemAtIndex(list.getCurrentIndex()).getTitle();
                    this.mWebChromeClient.onReceivedTitle(view, previousTitle);
                }
            }
        }

        public void onReceivedTitle() {
            this.mIsOnReceivedTitle = true;
        }
    }

    private void fixedStillAttached() {
        ViewParent parent = getParent();
        if (parent instanceof ViewGroup) {
            ViewGroup mWebViewContainer = (ViewGroup) getParent();
            mWebViewContainer.removeAllViewsInLayout();
        }
    }

    private void releaseConfigCallback() {
        if (Build.VERSION.SDK_INT < 16) {
            try {
                Field field = WebView.class.getDeclaredField("mWebViewCore");
                Field field2 = field.getType().getDeclaredField("mBrowserFrame").getType().getDeclaredField("sConfigCallback");
                field2.setAccessible(true);
                field2.set(null, null);
                return;
            } catch (IllegalAccessException e) {
                if (LogUtils.isDebug()) {
                    e.printStackTrace();
                    return;
                }
                return;
            } catch (NoSuchFieldException e2) {
                if (LogUtils.isDebug()) {
                    e2.printStackTrace();
                    return;
                }
                return;
            }
        }
        if (Build.VERSION.SDK_INT < 19) {
            try {
                Field sConfigCallback = Class.forName("android.webkit.BrowserFrame").getDeclaredField("sConfigCallback");
                if (sConfigCallback != null) {
                    sConfigCallback.setAccessible(true);
                    sConfigCallback.set(null, null);
                }
            } catch (ClassNotFoundException e3) {
                if (LogUtils.isDebug()) {
                    e3.printStackTrace();
                }
            } catch (IllegalAccessException e4) {
                if (LogUtils.isDebug()) {
                    e4.printStackTrace();
                }
            } catch (NoSuchFieldException e5) {
                if (LogUtils.isDebug()) {
                    e5.printStackTrace();
                }
            }
        }
    }

    protected void trySetWebDebuggEnabled() {
        if (LogUtils.isDebug() && Build.VERSION.SDK_INT >= 19) {
            try {
                Method method = WebView.class.getMethod("setWebContentsDebuggingEnabled", Boolean.TYPE);
                method.invoke(null, true);
            } catch (Throwable e) {
                if (LogUtils.isDebug()) {
                    e.printStackTrace();
                }
            }
        }
    }

    protected boolean removeSearchBoxJavaBridge() {
        try {
            if (Build.VERSION.SDK_INT >= 11 && Build.VERSION.SDK_INT < 17) {
                Method method = getClass().getMethod("removeJavascriptInterface", String.class);
                method.invoke(this, "searchBoxJavaBridge_");
                return true;
            }
        } catch (Exception e) {
            if (LogUtils.isDebug()) {
                e.printStackTrace();
            }
        }
        return false;
    }

    protected void fixedAccessibilityInjectorException() {
        if (Build.VERSION.SDK_INT == 17 && this.mIsAccessibilityEnabledOriginal == null && isAccessibilityEnabled()) {
            this.mIsAccessibilityEnabledOriginal = true;
            setAccessibilityEnabled(false);
        }
    }

    protected void fixedAccessibilityInjectorExceptionForOnPageFinished(String url) {
        if (Build.VERSION.SDK_INT == 16 && getSettings().getJavaScriptEnabled() && this.mIsAccessibilityEnabledOriginal == null && isAccessibilityEnabled()) {
            try {
                try {
                    URLEncoder.encode(String.valueOf(new URI(url)), "utf-8");
                } catch (IllegalArgumentException e) {
                    if ("bad parameter".equals(e.getMessage())) {
                        this.mIsAccessibilityEnabledOriginal = true;
                        setAccessibilityEnabled(false);
                        LogUtils.safeCheckCrash(TAG, "fixedAccessibilityInjectorExceptionForOnPageFinished.url = " + url, e);
                    }
                }
            } catch (Throwable e2) {
                if (LogUtils.isDebug()) {
                    LogUtils.e(TAG, "fixedAccessibilityInjectorExceptionForOnPageFinished", e2);
                }
            }
        }
    }

    private boolean isAccessibilityEnabled() {
        AccessibilityManager am = (AccessibilityManager) getContext().getSystemService("accessibility");
        return am.isEnabled();
    }

    private void setAccessibilityEnabled(boolean enabled) {
        AccessibilityManager am = (AccessibilityManager) getContext().getSystemService("accessibility");
        try {
            Method setAccessibilityState = am.getClass().getDeclaredMethod("setAccessibilityState", Boolean.TYPE);
            setAccessibilityState.setAccessible(true);
            setAccessibilityState.invoke(am, Boolean.valueOf(enabled));
            setAccessibilityState.setAccessible(false);
        } catch (Throwable e) {
            if (LogUtils.isDebug()) {
                LogUtils.e(TAG, "setAccessibilityEnabled", e);
            }
        }
    }

    private void resetAccessibilityEnabled() {
        Boolean bool = this.mIsAccessibilityEnabledOriginal;
        if (bool != null) {
            setAccessibilityEnabled(bool.booleanValue());
        }
    }
}
