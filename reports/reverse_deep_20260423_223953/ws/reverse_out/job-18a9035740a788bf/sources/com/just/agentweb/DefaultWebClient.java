package com.just.agentweb;

import android.app.Activity;
import android.content.ActivityNotFoundException;
import android.content.Intent;
import android.content.pm.ActivityInfo;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.graphics.Bitmap;
import android.net.Uri;
import android.net.http.SslError;
import android.os.Handler;
import android.os.Message;
import android.text.TextUtils;
import android.view.KeyEvent;
import android.webkit.HttpAuthHandler;
import android.webkit.SslErrorHandler;
import android.webkit.WebResourceError;
import android.webkit.WebResourceRequest;
import android.webkit.WebResourceResponse;
import android.webkit.WebView;
import androidx.core.net.MailTo;
import com.alipay.sdk.app.H5PayCallback;
import com.alipay.sdk.app.PayTask;
import com.alipay.sdk.util.H5PayResultModel;
import java.lang.ref.WeakReference;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.net.URISyntaxException;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/* JADX INFO: loaded from: classes3.dex */
public class DefaultWebClient extends MiddlewareWebClientBase {
    public static final String ALIPAYS_SCHEME = "alipays://";
    public static final int ASK_USER_OPEN_OTHER_PAGE = 250;
    private static final int CONSTANTS_ABNORMAL_BIG = 7;
    public static final int DERECT_OPEN_OTHER_PAGE = 1001;
    public static final int DISALLOW_OPEN_OTHER_APP = 62;
    private static final boolean HAS_ALIPAY_LIB;
    public static final String HTTPS_SCHEME = "https://";
    public static final String HTTP_SCHEME = "http://";
    public static final String INTENT_SCHEME = "intent://";
    public static final String SCHEME_SMS = "sms:";
    private static final String TAG = DefaultWebClient.class.getSimpleName();
    public static final String WEBCHAT_PAY_SCHEME = "weixin://wap/pay?";
    private WeakReference<AbsAgentWebUIController> mAgentWebUIController;
    private Handler.Callback mCallback;
    private Set<String> mErrorUrlsSet;
    private boolean mIsInterceptUnkownUrl;
    private Object mPayTask;
    private int mUrlHandleWays;
    private Set<String> mWaittingFinishSet;
    private WeakReference<Activity> mWeakReference;
    private WebView mWebView;
    private android.webkit.WebViewClient mWebViewClient;
    private Method onMainFrameErrorMethod;
    private boolean webClientHelper;

    static {
        boolean tag = true;
        try {
            Class.forName("com.alipay.sdk.app.PayTask");
        } catch (Throwable th) {
            tag = false;
        }
        HAS_ALIPAY_LIB = tag;
        LogUtils.i(TAG, "HAS_ALIPAY_LIB:" + HAS_ALIPAY_LIB);
    }

    DefaultWebClient(Builder builder) {
        super(builder.mClient);
        this.mWeakReference = null;
        this.webClientHelper = true;
        this.mUrlHandleWays = 250;
        this.mIsInterceptUnkownUrl = true;
        this.mAgentWebUIController = null;
        this.mCallback = null;
        this.onMainFrameErrorMethod = null;
        this.mErrorUrlsSet = new HashSet();
        this.mWaittingFinishSet = new HashSet();
        this.mWebView = builder.mWebView;
        this.mWebViewClient = builder.mClient;
        this.mWeakReference = new WeakReference<>(builder.mActivity);
        this.webClientHelper = builder.mWebClientHelper;
        this.mAgentWebUIController = new WeakReference<>(AgentWebUtils.getAgentWebUIControllerByWebView(builder.mWebView));
        this.mIsInterceptUnkownUrl = builder.mIsInterceptUnkownScheme;
        if (builder.mUrlHandleWays <= 0) {
            this.mUrlHandleWays = 250;
        } else {
            this.mUrlHandleWays = builder.mUrlHandleWays;
        }
    }

    @Override // com.just.agentweb.WebViewClientDelegate, android.webkit.WebViewClient
    public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
        String url = request.getUrl().toString();
        if (url.startsWith(HTTP_SCHEME) || url.startsWith(HTTPS_SCHEME)) {
            return this.webClientHelper && HAS_ALIPAY_LIB && isAlipay(view, url);
        }
        if (!this.webClientHelper) {
            return super.shouldOverrideUrlLoading(view, request);
        }
        if (handleCommonLink(url)) {
            return true;
        }
        if (url.startsWith(INTENT_SCHEME)) {
            handleIntentUrl(url);
            LogUtils.i(TAG, "intent url ");
            return true;
        }
        if (url.startsWith(WEBCHAT_PAY_SCHEME)) {
            LogUtils.i(TAG, "lookup wechat to pay ~~");
            startActivity(url);
            return true;
        }
        if (url.startsWith(ALIPAYS_SCHEME) && lookup(url)) {
            LogUtils.i(TAG, "alipays url lookup alipay ~~ ");
            return true;
        }
        if (queryActiviesNumber(url) > 0 && deepLink(url)) {
            LogUtils.i(TAG, "intercept url:" + url);
            return true;
        }
        if (this.mIsInterceptUnkownUrl) {
            LogUtils.i(TAG, "intercept UnkownUrl :" + request.getUrl());
            return true;
        }
        return super.shouldOverrideUrlLoading(view, request);
    }

    @Override // com.just.agentweb.WebViewClientDelegate, android.webkit.WebViewClient
    public WebResourceResponse shouldInterceptRequest(WebView view, String url) {
        return super.shouldInterceptRequest(view, url);
    }

    @Override // com.just.agentweb.WebViewClientDelegate, android.webkit.WebViewClient
    public void onReceivedHttpAuthRequest(WebView view, HttpAuthHandler handler, String host, String realm) {
        super.onReceivedHttpAuthRequest(view, handler, host, realm);
    }

    private boolean deepLink(String url) {
        ResolveInfo resolveInfo;
        int i = this.mUrlHandleWays;
        if (i != 250) {
            if (i != 1001) {
                return false;
            }
            lookup(url);
            return true;
        }
        Activity mActivity = this.mWeakReference.get();
        if (mActivity == null || (resolveInfo = lookupResolveInfo(url)) == null) {
            return false;
        }
        ActivityInfo activityInfo = resolveInfo.activityInfo;
        LogUtils.e(TAG, "resolve package:" + resolveInfo.activityInfo.packageName + " app package:" + mActivity.getPackageName());
        if (activityInfo != null && !TextUtils.isEmpty(activityInfo.packageName) && activityInfo.packageName.equals(mActivity.getPackageName())) {
            return lookup(url);
        }
        if (this.mAgentWebUIController.get() != null) {
            AbsAgentWebUIController absAgentWebUIController = this.mAgentWebUIController.get();
            WebView webView = this.mWebView;
            absAgentWebUIController.onOpenPagePrompt(webView, webView.getUrl(), getCallback(url));
        }
        return true;
    }

    @Override // com.just.agentweb.WebViewClientDelegate, android.webkit.WebViewClient
    public WebResourceResponse shouldInterceptRequest(WebView view, WebResourceRequest request) {
        return super.shouldInterceptRequest(view, request);
    }

    @Override // com.just.agentweb.WebViewClientDelegate, android.webkit.WebViewClient
    public boolean shouldOverrideUrlLoading(WebView view, String url) {
        if (url.startsWith(HTTP_SCHEME) || url.startsWith(HTTPS_SCHEME)) {
            return this.webClientHelper && HAS_ALIPAY_LIB && isAlipay(view, url);
        }
        if (!this.webClientHelper) {
            return false;
        }
        if (handleCommonLink(url)) {
            return true;
        }
        if (url.startsWith(INTENT_SCHEME)) {
            handleIntentUrl(url);
            return true;
        }
        if (url.startsWith(WEBCHAT_PAY_SCHEME)) {
            startActivity(url);
            return true;
        }
        if (url.startsWith(ALIPAYS_SCHEME) && lookup(url)) {
            return true;
        }
        if (queryActiviesNumber(url) > 0 && deepLink(url)) {
            LogUtils.i(TAG, "intercept OtherAppScheme");
            return true;
        }
        if (this.mIsInterceptUnkownUrl) {
            LogUtils.i(TAG, "intercept InterceptUnkownScheme : " + url);
            return true;
        }
        return super.shouldOverrideUrlLoading(view, url);
    }

    private int queryActiviesNumber(String url) {
        try {
            if (this.mWeakReference.get() == null) {
                return 0;
            }
            Intent intent = Intent.parseUri(url, 1);
            PackageManager mPackageManager = this.mWeakReference.get().getPackageManager();
            List<ResolveInfo> mResolveInfos = mPackageManager.queryIntentActivities(intent, 65536);
            if (mResolveInfos == null) {
                return 0;
            }
            return mResolveInfos.size();
        } catch (URISyntaxException ignore) {
            if (LogUtils.isDebug()) {
                ignore.printStackTrace();
            }
            return 0;
        }
    }

    private void handleIntentUrl(String intentUrl) {
        try {
            if (!TextUtils.isEmpty(intentUrl) && intentUrl.startsWith(INTENT_SCHEME)) {
                if (lookup(intentUrl)) {
                }
            }
        } catch (Throwable e) {
            if (LogUtils.isDebug()) {
                e.printStackTrace();
            }
        }
    }

    private ResolveInfo lookupResolveInfo(String url) {
        try {
            Activity mActivity = this.mWeakReference.get();
            if (mActivity == null) {
                return null;
            }
            PackageManager packageManager = mActivity.getPackageManager();
            Intent intent = Intent.parseUri(url, 1);
            ResolveInfo info = packageManager.resolveActivity(intent, 65536);
            return info;
        } catch (Throwable ignore) {
            if (LogUtils.isDebug()) {
                ignore.printStackTrace();
            }
            return null;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public boolean lookup(String url) {
        try {
            Activity mActivity = this.mWeakReference.get();
            if (mActivity == null) {
                return true;
            }
            PackageManager packageManager = mActivity.getPackageManager();
            Intent intent = Intent.parseUri(url, 1);
            ResolveInfo info = packageManager.resolveActivity(intent, 65536);
            if (info != null) {
                mActivity.startActivity(intent);
                return true;
            }
            return false;
        } catch (Throwable ignore) {
            if (LogUtils.isDebug()) {
                ignore.printStackTrace();
                return false;
            }
            return false;
        }
    }

    private boolean isAlipay(final WebView view, String url) {
        try {
            Activity mActivity = this.mWeakReference.get();
            if (mActivity == null) {
                return false;
            }
            if (this.mPayTask == null) {
                Constructor<?> mConstructor = Class.forName("com.alipay.sdk.app.PayTask").getConstructor(Activity.class);
                this.mPayTask = mConstructor.newInstance(mActivity);
            }
            PayTask task = (PayTask) this.mPayTask;
            boolean isIntercepted = task.payInterceptorWithUrl(url, true, new H5PayCallback() { // from class: com.just.agentweb.DefaultWebClient.1
                public void onPayResult(H5PayResultModel result) {
                    final String url2 = result.getReturnUrl();
                    if (!TextUtils.isEmpty(url2)) {
                        AgentWebUtils.runInUiThread(new Runnable() { // from class: com.just.agentweb.DefaultWebClient.1.1
                            @Override // java.lang.Runnable
                            public void run() {
                                view.loadUrl(url2);
                            }
                        });
                    }
                }
            });
            if (isIntercepted) {
                LogUtils.i(TAG, "alipay-isIntercepted:" + isIntercepted + "  url:" + url);
            }
            return isIntercepted;
        } catch (Throwable th) {
            boolean z = AgentWebConfig.DEBUG;
            return false;
        }
    }

    private boolean handleCommonLink(String url) {
        if (!url.startsWith("tel:") && !url.startsWith(SCHEME_SMS) && !url.startsWith(MailTo.MAILTO_SCHEME) && !url.startsWith("geo:0,0?q=")) {
            return false;
        }
        try {
            Activity mActivity = this.mWeakReference.get();
            if (mActivity == null) {
                return false;
            }
            Intent intent = new Intent("android.intent.action.VIEW");
            intent.setData(Uri.parse(url));
            mActivity.startActivity(intent);
            return true;
        } catch (ActivityNotFoundException ignored) {
            if (AgentWebConfig.DEBUG) {
                ignored.printStackTrace();
                return true;
            }
            return true;
        }
    }

    @Override // com.just.agentweb.WebViewClientDelegate, android.webkit.WebViewClient
    public void onPageStarted(WebView view, String url, Bitmap favicon) {
        if (!this.mWaittingFinishSet.contains(url)) {
            this.mWaittingFinishSet.add(url);
        }
        super.onPageStarted(view, url, favicon);
    }

    @Override // com.just.agentweb.WebViewClientDelegate, android.webkit.WebViewClient
    public void onReceivedSslError(WebView view, SslErrorHandler handler, SslError error) {
        if (this.mAgentWebUIController.get() != null) {
            this.mAgentWebUIController.get().onShowSslCertificateErrorDialog(view, handler, error);
        }
    }

    @Override // com.just.agentweb.WebViewClientDelegate, android.webkit.WebViewClient
    public void onReceivedError(WebView view, int errorCode, String description, String failingUrl) {
        LogUtils.i(TAG, "onReceivedError：" + description + "  CODE:" + errorCode);
        if ((failingUrl == null && errorCode != -12) || errorCode == -1) {
            return;
        }
        if (errorCode != -2 && failingUrl != null && !failingUrl.equals(view.getUrl()) && !failingUrl.equals(view.getOriginalUrl())) {
            return;
        }
        onMainFrameError(view, errorCode, description, failingUrl);
    }

    @Override // com.just.agentweb.WebViewClientDelegate, android.webkit.WebViewClient
    public void doUpdateVisitedHistory(WebView view, String url, boolean isReload) {
        if (!this.mWaittingFinishSet.contains(url)) {
            this.mWaittingFinishSet.add(url);
        }
        super.doUpdateVisitedHistory(view, url, isReload);
    }

    @Override // com.just.agentweb.WebViewClientDelegate, android.webkit.WebViewClient
    public void onReceivedError(WebView view, WebResourceRequest request, WebResourceError error) {
        String failingUrl = request.getUrl().toString();
        int errorCode = error.getErrorCode();
        if (!request.isForMainFrame()) {
            return;
        }
        if ((failingUrl == null && errorCode != -12) || errorCode == -1) {
            return;
        }
        LogUtils.i(TAG, "onReceivedError:" + ((Object) error.getDescription()) + " code:" + error.getErrorCode() + " failingUrl:" + failingUrl + " getUrl:" + view.getUrl() + " getOriginalUrl:" + view.getOriginalUrl());
        if (errorCode != -2 && failingUrl != null && !failingUrl.equals(view.getUrl()) && !failingUrl.equals(view.getOriginalUrl())) {
            return;
        }
        onMainFrameError(view, error.getErrorCode(), error.getDescription().toString(), request.getUrl().toString());
    }

    /* JADX WARN: Code restructure failed: missing block: B:9:0x0036, code lost:
    
        if (r0 != null) goto L21;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private void onMainFrameError(android.webkit.WebView r11, int r12, java.lang.String r13, java.lang.String r14) {
        /*
            r10 = this;
            java.util.Set<java.lang.String> r0 = r10.mErrorUrlsSet
            r0.add(r14)
            android.webkit.WebViewClient r0 = r10.mWebViewClient
            if (r0 == 0) goto L5f
            boolean r1 = r10.webClientHelper
            if (r1 == 0) goto L5f
            java.lang.reflect.Method r1 = r10.onMainFrameErrorMethod
            r2 = 4
            r3 = 3
            r4 = 2
            r5 = 1
            r6 = 0
            r7 = 5
            if (r1 != 0) goto L38
            java.lang.Class[] r8 = new java.lang.Class[r7]
            java.lang.Class<com.just.agentweb.AbsAgentWebUIController> r9 = com.just.agentweb.AbsAgentWebUIController.class
            r8[r6] = r9
            java.lang.Class<android.webkit.WebView> r9 = android.webkit.WebView.class
            r8[r5] = r9
            java.lang.Class r9 = java.lang.Integer.TYPE
            r8[r4] = r9
            java.lang.Class<java.lang.String> r9 = java.lang.String.class
            r8[r3] = r9
            java.lang.Class<java.lang.String> r9 = java.lang.String.class
            r8[r2] = r9
            java.lang.String r9 = "onMainFrameError"
            java.lang.reflect.Method r0 = com.just.agentweb.AgentWebUtils.isExistMethod(r0, r9, r8)
            r1 = r0
            r10.onMainFrameErrorMethod = r0
            if (r0 == 0) goto L5f
        L38:
            android.webkit.WebViewClient r0 = r10.mWebViewClient     // Catch: java.lang.Throwable -> L54
            java.lang.Object[] r7 = new java.lang.Object[r7]     // Catch: java.lang.Throwable -> L54
            java.lang.ref.WeakReference<com.just.agentweb.AbsAgentWebUIController> r8 = r10.mAgentWebUIController     // Catch: java.lang.Throwable -> L54
            java.lang.Object r8 = r8.get()     // Catch: java.lang.Throwable -> L54
            r7[r6] = r8     // Catch: java.lang.Throwable -> L54
            r7[r5] = r11     // Catch: java.lang.Throwable -> L54
            java.lang.Integer r5 = java.lang.Integer.valueOf(r12)     // Catch: java.lang.Throwable -> L54
            r7[r4] = r5     // Catch: java.lang.Throwable -> L54
            r7[r3] = r13     // Catch: java.lang.Throwable -> L54
            r7[r2] = r14     // Catch: java.lang.Throwable -> L54
            r1.invoke(r0, r7)     // Catch: java.lang.Throwable -> L54
            goto L5e
        L54:
            r0 = move-exception
            boolean r2 = com.just.agentweb.LogUtils.isDebug()
            if (r2 == 0) goto L5e
            r0.printStackTrace()
        L5e:
            return
        L5f:
            java.lang.ref.WeakReference<com.just.agentweb.AbsAgentWebUIController> r0 = r10.mAgentWebUIController
            java.lang.Object r0 = r0.get()
            if (r0 == 0) goto L72
            java.lang.ref.WeakReference<com.just.agentweb.AbsAgentWebUIController> r0 = r10.mAgentWebUIController
            java.lang.Object r0 = r0.get()
            com.just.agentweb.AbsAgentWebUIController r0 = (com.just.agentweb.AbsAgentWebUIController) r0
            r0.onMainFrameError(r11, r12, r13, r14)
        L72:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.just.agentweb.DefaultWebClient.onMainFrameError(android.webkit.WebView, int, java.lang.String, java.lang.String):void");
    }

    @Override // com.just.agentweb.WebViewClientDelegate, android.webkit.WebViewClient
    public void onPageFinished(WebView view, String url) {
        if (!this.mErrorUrlsSet.contains(url) && this.mWaittingFinishSet.contains(url)) {
            if (this.mAgentWebUIController.get() != null) {
                this.mAgentWebUIController.get().onShowMainFrame();
            }
        } else {
            view.setVisibility(0);
        }
        if (this.mWaittingFinishSet.contains(url)) {
            this.mWaittingFinishSet.remove(url);
        }
        if (!this.mErrorUrlsSet.isEmpty()) {
            this.mErrorUrlsSet.clear();
        }
        super.onPageFinished(view, url);
    }

    @Override // com.just.agentweb.WebViewClientDelegate, android.webkit.WebViewClient
    public boolean shouldOverrideKeyEvent(WebView view, KeyEvent event) {
        return super.shouldOverrideKeyEvent(view, event);
    }

    private void startActivity(String url) {
        try {
            if (this.mWeakReference.get() == null) {
                return;
            }
            Intent intent = new Intent();
            intent.setAction("android.intent.action.VIEW");
            intent.setData(Uri.parse(url));
            this.mWeakReference.get().startActivity(intent);
        } catch (Exception e) {
            if (LogUtils.isDebug()) {
                e.printStackTrace();
            }
        }
    }

    @Override // com.just.agentweb.WebViewClientDelegate, android.webkit.WebViewClient
    public void onReceivedHttpError(WebView view, WebResourceRequest request, WebResourceResponse errorResponse) {
        super.onReceivedHttpError(view, request, errorResponse);
    }

    @Override // com.just.agentweb.WebViewClientDelegate, android.webkit.WebViewClient
    public void onScaleChanged(WebView view, float oldScale, float newScale) {
        LogUtils.i(TAG, "onScaleChanged:" + oldScale + "   n:" + newScale);
        if (newScale - oldScale > 7.0f) {
            view.setInitialScale((int) ((oldScale / newScale) * 100.0f));
        }
    }

    private Handler.Callback getCallback(final String url) {
        Handler.Callback callback = this.mCallback;
        if (callback != null) {
            return callback;
        }
        Handler.Callback callback2 = new Handler.Callback() { // from class: com.just.agentweb.DefaultWebClient.2
            @Override // android.os.Handler.Callback
            public boolean handleMessage(Message msg) {
                if (msg.what != 1) {
                    return true;
                }
                DefaultWebClient.this.lookup(url);
                return true;
            }
        };
        this.mCallback = callback2;
        return callback2;
    }

    public static Builder createBuilder() {
        return new Builder();
    }

    public static class Builder {
        private Activity mActivity;
        private android.webkit.WebViewClient mClient;
        private boolean mIsInterceptUnkownScheme = true;
        private PermissionInterceptor mPermissionInterceptor;
        private int mUrlHandleWays;
        private boolean mWebClientHelper;
        private WebView mWebView;

        public Builder setActivity(Activity activity) {
            this.mActivity = activity;
            return this;
        }

        public Builder setClient(android.webkit.WebViewClient client) {
            this.mClient = client;
            return this;
        }

        public Builder setWebClientHelper(boolean webClientHelper) {
            this.mWebClientHelper = webClientHelper;
            return this;
        }

        public Builder setPermissionInterceptor(PermissionInterceptor permissionInterceptor) {
            this.mPermissionInterceptor = permissionInterceptor;
            return this;
        }

        public Builder setWebView(WebView webView) {
            this.mWebView = webView;
            return this;
        }

        public Builder setInterceptUnkownUrl(boolean interceptUnkownScheme) {
            this.mIsInterceptUnkownScheme = interceptUnkownScheme;
            return this;
        }

        public Builder setUrlHandleWays(int urlHandleWays) {
            this.mUrlHandleWays = urlHandleWays;
            return this;
        }

        public DefaultWebClient build() {
            return new DefaultWebClient(this);
        }
    }

    public enum OpenOtherPageWays {
        DERECT(1001),
        ASK(250),
        DISALLOW(62);

        int code;

        OpenOtherPageWays(int code) {
            this.code = code;
        }
    }
}
