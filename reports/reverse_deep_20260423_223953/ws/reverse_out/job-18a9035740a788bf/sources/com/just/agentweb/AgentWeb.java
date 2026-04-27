package com.just.agentweb;

import android.app.Activity;
import android.text.TextUtils;
import android.view.KeyEvent;
import android.view.View;
import android.view.ViewGroup;
import android.webkit.WebView;
import androidx.collection.ArrayMap;
import androidx.fragment.app.Fragment;
import com.just.agentweb.DefaultWebClient;
import java.lang.ref.WeakReference;
import java.util.Map;

/* JADX INFO: loaded from: classes3.dex */
public final class AgentWeb {
    private static final int ACTIVITY_TAG = 0;
    private static final int FRAGMENT_TAG = 1;
    private static final String TAG = AgentWeb.class.getSimpleName();
    private Activity mActivity;
    private AgentWeb mAgentWeb;
    private AgentWebJsInterfaceCompat mAgentWebJsInterfaceCompat;
    private IAgentWebSettings mAgentWebSettings;
    private boolean mEnableIndicator;
    private EventInterceptor mEventInterceptor;
    private IEventHandler mIEventHandler;
    private IUrlLoader mIUrlLoader;
    private IVideo mIVideo;
    private IndicatorController mIndicatorController;
    private boolean mIsInterceptUnkownUrl;
    private ArrayMap<String, Object> mJavaObjects;
    private JsAccessEntrace mJsAccessEntrace;
    private JsInterfaceHolder mJsInterfaceHolder;
    private MiddlewareWebClientBase mMiddleWrareWebClientBaseHeader;
    private MiddlewareWebChromeBase mMiddlewareWebChromeBaseHeader;
    private PermissionInterceptor mPermissionInterceptor;
    private SecurityType mSecurityType;
    private int mTagTarget;
    private android.webkit.WebChromeClient mTargetChromeClient;
    private int mUrlHandleWays;
    private ViewGroup mViewGroup;
    private WebChromeClient mWebChromeClient;
    private boolean mWebClientHelper;
    private WebCreator mWebCreator;
    private WebLifeCycle mWebLifeCycle;
    private WebListenerManager mWebListenerManager;
    private WebSecurityCheckLogic mWebSecurityCheckLogic;
    private WebSecurityController<WebSecurityCheckLogic> mWebSecurityController;
    private WebViewClient mWebViewClient;

    public enum SecurityType {
        DEFAULT_CHECK,
        STRICT_CHECK
    }

    /* JADX WARN: Multi-variable type inference failed */
    private AgentWeb(AgentBuilder agentBuilder) {
        Object[] objArr = 0;
        this.mAgentWeb = null;
        this.mJavaObjects = new ArrayMap<>();
        this.mTagTarget = 0;
        this.mWebSecurityController = null;
        this.mWebSecurityCheckLogic = null;
        this.mSecurityType = SecurityType.DEFAULT_CHECK;
        this.mAgentWebJsInterfaceCompat = null;
        this.mJsAccessEntrace = null;
        this.mIUrlLoader = null;
        this.mIVideo = null;
        this.mWebClientHelper = true;
        this.mIsInterceptUnkownUrl = true;
        this.mUrlHandleWays = -1;
        this.mJsInterfaceHolder = null;
        this.mTagTarget = agentBuilder.mTag;
        this.mActivity = agentBuilder.mActivity;
        this.mViewGroup = agentBuilder.mViewGroup;
        this.mIEventHandler = agentBuilder.mIEventHandler;
        this.mEnableIndicator = agentBuilder.mEnableIndicator;
        this.mWebCreator = agentBuilder.mWebCreator == null ? configWebCreator(agentBuilder.mBaseIndicatorView, agentBuilder.mIndex, agentBuilder.mLayoutParams, agentBuilder.mIndicatorColor, agentBuilder.mHeight, agentBuilder.mWebView, agentBuilder.mWebLayout) : agentBuilder.mWebCreator;
        this.mIndicatorController = agentBuilder.mIndicatorController;
        this.mWebChromeClient = agentBuilder.mWebChromeClient;
        this.mWebViewClient = agentBuilder.mWebViewClient;
        this.mAgentWeb = this;
        this.mAgentWebSettings = agentBuilder.mAgentWebSettings;
        if (agentBuilder.mJavaObject != null && !agentBuilder.mJavaObject.isEmpty()) {
            this.mJavaObjects.putAll((Map<? extends String, ? extends Object>) agentBuilder.mJavaObject);
            LogUtils.i(TAG, "mJavaObject size:" + this.mJavaObjects.size());
        }
        this.mPermissionInterceptor = agentBuilder.mPermissionInterceptor != null ? new PermissionInterceptorWrapper(agentBuilder.mPermissionInterceptor) : null;
        this.mSecurityType = agentBuilder.mSecurityType;
        this.mIUrlLoader = new UrlLoaderImpl(this.mWebCreator.create().getWebView(), agentBuilder.mHttpHeaders);
        if (this.mWebCreator.getWebParentLayout() instanceof WebParentLayout) {
            WebParentLayout webParentLayout = (WebParentLayout) this.mWebCreator.getWebParentLayout();
            webParentLayout.bindController(agentBuilder.mAgentWebUIController == null ? AgentWebUIControllerImplBase.build() : agentBuilder.mAgentWebUIController);
            webParentLayout.setErrorLayoutRes(agentBuilder.mErrorLayout, agentBuilder.mReloadId);
            webParentLayout.setErrorView(agentBuilder.mErrorView);
        }
        this.mWebLifeCycle = new DefaultWebLifeCycleImpl(this.mWebCreator.getWebView());
        this.mWebSecurityController = new WebSecurityControllerImpl(this.mWebCreator.getWebView(), this.mAgentWeb.mJavaObjects, this.mSecurityType);
        this.mWebClientHelper = agentBuilder.mWebClientHelper;
        this.mIsInterceptUnkownUrl = agentBuilder.mIsInterceptUnkownUrl;
        if (agentBuilder.mOpenOtherPage != null) {
            this.mUrlHandleWays = agentBuilder.mOpenOtherPage.code;
        }
        this.mMiddleWrareWebClientBaseHeader = agentBuilder.mMiddlewareWebClientBaseHeader;
        this.mMiddlewareWebChromeBaseHeader = agentBuilder.mChromeMiddleWareHeader;
        init();
    }

    public PermissionInterceptor getPermissionInterceptor() {
        return this.mPermissionInterceptor;
    }

    public WebLifeCycle getWebLifeCycle() {
        return this.mWebLifeCycle;
    }

    public JsAccessEntrace getJsAccessEntrace() {
        JsAccessEntrace mJsAccessEntrace = this.mJsAccessEntrace;
        if (mJsAccessEntrace == null) {
            JsAccessEntrace mJsAccessEntrace2 = JsAccessEntraceImpl.getInstance(this.mWebCreator.getWebView());
            this.mJsAccessEntrace = mJsAccessEntrace2;
            return mJsAccessEntrace2;
        }
        return mJsAccessEntrace;
    }

    public AgentWeb clearWebCache() {
        if (getWebCreator().getWebView() != null) {
            AgentWebUtils.clearWebViewAllCache(this.mActivity, getWebCreator().getWebView());
        } else {
            AgentWebUtils.clearWebViewAllCache(this.mActivity);
        }
        return this;
    }

    public static AgentBuilder with(Activity activity) {
        if (activity == null) {
            throw new NullPointerException("activity can not be null .");
        }
        return new AgentBuilder(activity);
    }

    public static AgentBuilder with(Fragment fragment) {
        Activity mActivity = fragment.getActivity();
        if (mActivity == null) {
            throw new NullPointerException("activity can not be null .");
        }
        return new AgentBuilder(mActivity, fragment);
    }

    public boolean handleKeyEvent(int keyCode, KeyEvent keyEvent) {
        if (this.mIEventHandler == null) {
            this.mIEventHandler = EventHandlerImpl.getInstantce(this.mWebCreator.getWebView(), getInterceptor());
        }
        return this.mIEventHandler.onKeyDown(keyCode, keyEvent);
    }

    public boolean back() {
        if (this.mIEventHandler == null) {
            this.mIEventHandler = EventHandlerImpl.getInstantce(this.mWebCreator.getWebView(), getInterceptor());
        }
        return this.mIEventHandler.back();
    }

    public WebCreator getWebCreator() {
        return this.mWebCreator;
    }

    public IEventHandler getIEventHandler() {
        IEventHandler iEventHandler = this.mIEventHandler;
        if (iEventHandler != null) {
            return iEventHandler;
        }
        EventHandlerImpl instantce = EventHandlerImpl.getInstantce(this.mWebCreator.getWebView(), getInterceptor());
        this.mIEventHandler = instantce;
        return instantce;
    }

    public IAgentWebSettings getAgentWebSettings() {
        return this.mAgentWebSettings;
    }

    public IndicatorController getIndicatorController() {
        return this.mIndicatorController;
    }

    public JsInterfaceHolder getJsInterfaceHolder() {
        return this.mJsInterfaceHolder;
    }

    public IUrlLoader getUrlLoader() {
        return this.mIUrlLoader;
    }

    public void destroy() {
        this.mWebLifeCycle.onDestroy();
    }

    public static class PreAgentWeb {
        private boolean isReady = false;
        private AgentWeb mAgentWeb;

        PreAgentWeb(AgentWeb agentWeb) {
            this.mAgentWeb = agentWeb;
        }

        public PreAgentWeb ready() {
            if (!this.isReady) {
                this.mAgentWeb.ready();
                this.isReady = true;
            }
            return this;
        }

        public AgentWeb get() {
            ready();
            return this.mAgentWeb;
        }

        public AgentWeb go(String url) {
            if (!this.isReady) {
                ready();
            }
            return this.mAgentWeb.go(url);
        }
    }

    private void doSafeCheck() {
        WebSecurityCheckLogic mWebSecurityCheckLogic = this.mWebSecurityCheckLogic;
        if (mWebSecurityCheckLogic == null) {
            WebSecurityLogicImpl webSecurityLogicImpl = WebSecurityLogicImpl.getInstance(this.mWebCreator.getWebViewType());
            mWebSecurityCheckLogic = webSecurityLogicImpl;
            this.mWebSecurityCheckLogic = webSecurityLogicImpl;
        }
        this.mWebSecurityController.check(mWebSecurityCheckLogic);
    }

    private void doCompat() {
        ArrayMap<String, Object> arrayMap = this.mJavaObjects;
        AgentWebJsInterfaceCompat agentWebJsInterfaceCompat = new AgentWebJsInterfaceCompat(this, this.mActivity);
        this.mAgentWebJsInterfaceCompat = agentWebJsInterfaceCompat;
        arrayMap.put("agentWeb", agentWebJsInterfaceCompat);
    }

    private WebCreator configWebCreator(BaseIndicatorView progressView, int index, ViewGroup.LayoutParams lp, int indicatorColor, int height_dp, WebView webView, IWebLayout webLayout) {
        if (progressView == null || !this.mEnableIndicator) {
            return this.mEnableIndicator ? new DefaultWebCreator(this.mActivity, this.mViewGroup, lp, index, indicatorColor, height_dp, webView, webLayout) : new DefaultWebCreator(this.mActivity, this.mViewGroup, lp, index, webView, webLayout);
        }
        return new DefaultWebCreator(this.mActivity, this.mViewGroup, lp, index, progressView, webView, webLayout);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public AgentWeb go(String url) {
        IndicatorController mIndicatorController;
        getUrlLoader().loadUrl(url);
        if (!TextUtils.isEmpty(url) && (mIndicatorController = getIndicatorController()) != null && mIndicatorController.offerIndicator() != null) {
            getIndicatorController().offerIndicator().show();
        }
        return this;
    }

    private EventInterceptor getInterceptor() {
        EventInterceptor eventInterceptor = this.mEventInterceptor;
        if (eventInterceptor != null) {
            return eventInterceptor;
        }
        IVideo iVideo = this.mIVideo;
        if (iVideo instanceof VideoImpl) {
            EventInterceptor eventInterceptor2 = (EventInterceptor) iVideo;
            this.mEventInterceptor = eventInterceptor2;
            return eventInterceptor2;
        }
        return null;
    }

    private void init() {
        doCompat();
        doSafeCheck();
    }

    private IVideo getIVideo() {
        IVideo iVideo = this.mIVideo;
        return iVideo == null ? new VideoImpl(this.mActivity, this.mWebCreator.getWebView()) : iVideo;
    }

    private android.webkit.WebViewClient getWebViewClient() {
        LogUtils.i(TAG, "getDelegate:" + this.mMiddleWrareWebClientBaseHeader);
        DefaultWebClient mDefaultWebClient = DefaultWebClient.createBuilder().setActivity(this.mActivity).setWebClientHelper(this.mWebClientHelper).setPermissionInterceptor(this.mPermissionInterceptor).setWebView(this.mWebCreator.getWebView()).setInterceptUnkownUrl(this.mIsInterceptUnkownUrl).setUrlHandleWays(this.mUrlHandleWays).build();
        MiddlewareWebClientBase header = this.mMiddleWrareWebClientBaseHeader;
        WebViewClient webViewClient = this.mWebViewClient;
        if (webViewClient != null) {
            webViewClient.enq(this.mMiddleWrareWebClientBaseHeader);
            header = this.mWebViewClient;
        }
        if (header != null) {
            MiddlewareWebClientBase tail = header;
            int count = 1;
            MiddlewareWebClientBase tmp = header;
            while (tmp.next() != null) {
                MiddlewareWebClientBase next = tmp.next();
                tmp = next;
                tail = next;
                count++;
            }
            LogUtils.i(TAG, "MiddlewareWebClientBase middleware count:" + count);
            tail.setDelegate(mDefaultWebClient);
            return header;
        }
        return mDefaultWebClient;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public AgentWeb ready() {
        AgentWebConfig.initCookiesManager(this.mActivity.getApplicationContext());
        IAgentWebSettings mAgentWebSettings = this.mAgentWebSettings;
        if (mAgentWebSettings == null) {
            AbsAgentWebSettings agentWebSettingsImpl = AgentWebSettingsImpl.getInstance();
            mAgentWebSettings = agentWebSettingsImpl;
            this.mAgentWebSettings = agentWebSettingsImpl;
        }
        if (mAgentWebSettings instanceof AbsAgentWebSettings) {
            ((AbsAgentWebSettings) mAgentWebSettings).bindAgentWeb(this);
        }
        if (this.mWebListenerManager == null && (mAgentWebSettings instanceof AbsAgentWebSettings)) {
            this.mWebListenerManager = (WebListenerManager) mAgentWebSettings;
        }
        mAgentWebSettings.toSetting(this.mWebCreator.getWebView());
        if (this.mJsInterfaceHolder == null) {
            this.mJsInterfaceHolder = JsInterfaceHolderImpl.getJsInterfaceHolder(this.mWebCreator, this.mSecurityType);
        }
        LogUtils.i(TAG, "mJavaObjects:" + this.mJavaObjects.size());
        ArrayMap<String, Object> arrayMap = this.mJavaObjects;
        if (arrayMap != null && !arrayMap.isEmpty()) {
            this.mJsInterfaceHolder.addJavaObjects(this.mJavaObjects);
        }
        WebListenerManager webListenerManager = this.mWebListenerManager;
        if (webListenerManager != null) {
            webListenerManager.setDownloader(this.mWebCreator.getWebView(), null);
            this.mWebListenerManager.setWebChromeClient(this.mWebCreator.getWebView(), getChromeClient());
            this.mWebListenerManager.setWebViewClient(this.mWebCreator.getWebView(), getWebViewClient());
        }
        return this;
    }

    private android.webkit.WebChromeClient getChromeClient() {
        IndicatorController mIndicatorController = this.mIndicatorController;
        if (mIndicatorController == null) {
            mIndicatorController = IndicatorHandler.getInstance().inJectIndicator(this.mWebCreator.offer());
        }
        Activity activity = this.mActivity;
        this.mIndicatorController = mIndicatorController;
        IVideo iVideo = getIVideo();
        this.mIVideo = iVideo;
        DefaultChromeClient mDefaultChromeClient = new DefaultChromeClient(activity, mIndicatorController, null, iVideo, this.mPermissionInterceptor, this.mWebCreator.getWebView());
        LogUtils.i(TAG, "WebChromeClient:" + this.mWebChromeClient);
        MiddlewareWebChromeBase header = this.mMiddlewareWebChromeBaseHeader;
        WebChromeClient webChromeClient = this.mWebChromeClient;
        if (webChromeClient != null) {
            webChromeClient.enq(header);
            header = this.mWebChromeClient;
        }
        if (header != null) {
            MiddlewareWebChromeBase tail = header;
            int count = 1;
            MiddlewareWebChromeBase tmp = header;
            while (tmp.next() != null) {
                MiddlewareWebChromeBase next = tmp.next();
                tmp = next;
                tail = next;
                count++;
            }
            LogUtils.i(TAG, "MiddlewareWebClientBase middleware count:" + count);
            tail.setDelegate(mDefaultChromeClient);
            this.mTargetChromeClient = header;
            return header;
        }
        this.mTargetChromeClient = mDefaultChromeClient;
        return mDefaultChromeClient;
    }

    public static final class AgentBuilder {
        private Activity mActivity;
        private IAgentWebSettings mAgentWebSettings;
        private AbsAgentWebUIController mAgentWebUIController;
        private BaseIndicatorView mBaseIndicatorView;
        private int mErrorLayout;
        private View mErrorView;
        private Fragment mFragment;
        private IEventHandler mIEventHandler;
        private boolean mIsNeedDefaultProgress;
        private ArrayMap<String, Object> mJavaObject;
        private MiddlewareWebClientBase mMiddlewareWebClientBaseHeader;
        private MiddlewareWebClientBase mMiddlewareWebClientBaseTail;
        private int mReloadId;
        private int mTag;
        private ViewGroup mViewGroup;
        private WebChromeClient mWebChromeClient;
        private WebCreator mWebCreator;
        private WebView mWebView;
        private WebViewClient mWebViewClient;
        private int mIndex = -1;
        private IndicatorController mIndicatorController = null;
        private boolean mEnableIndicator = true;
        private ViewGroup.LayoutParams mLayoutParams = null;
        private int mIndicatorColor = -1;
        private HttpHeaders mHttpHeaders = null;
        private int mHeight = -1;
        private SecurityType mSecurityType = SecurityType.DEFAULT_CHECK;
        private boolean mWebClientHelper = true;
        private IWebLayout mWebLayout = null;
        private PermissionInterceptor mPermissionInterceptor = null;
        private DefaultWebClient.OpenOtherPageWays mOpenOtherPage = null;
        private boolean mIsInterceptUnkownUrl = true;
        private MiddlewareWebChromeBase mChromeMiddleWareHeader = null;
        private MiddlewareWebChromeBase mChromeMiddleWareTail = null;

        public AgentBuilder(Activity activity, Fragment fragment) {
            this.mTag = -1;
            this.mActivity = activity;
            this.mFragment = fragment;
            this.mTag = 1;
        }

        public AgentBuilder(Activity activity) {
            this.mTag = -1;
            this.mActivity = activity;
            this.mTag = 0;
        }

        public IndicatorBuilder setAgentWebParent(ViewGroup v, ViewGroup.LayoutParams lp) {
            this.mViewGroup = v;
            this.mLayoutParams = lp;
            return new IndicatorBuilder(this);
        }

        public IndicatorBuilder setAgentWebParent(ViewGroup v, int index, ViewGroup.LayoutParams lp) {
            this.mViewGroup = v;
            this.mLayoutParams = lp;
            this.mIndex = index;
            return new IndicatorBuilder(this);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public PreAgentWeb buildAgentWeb() {
            if (this.mTag == 1 && this.mViewGroup == null) {
                throw new NullPointerException("ViewGroup is null,Please check your parameters .");
            }
            return new PreAgentWeb(HookManager.hookAgentWeb(new AgentWeb(this), this));
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void addJavaObject(String key, Object o) {
            if (this.mJavaObject == null) {
                this.mJavaObject = new ArrayMap<>();
            }
            this.mJavaObject.put(key, o);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void addHeader(String baseUrl, String k, String v) {
            if (this.mHttpHeaders == null) {
                this.mHttpHeaders = HttpHeaders.create();
            }
            this.mHttpHeaders.additionalHttpHeader(baseUrl, k, v);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void addHeader(String baseUrl, Map<String, String> headers) {
            if (this.mHttpHeaders == null) {
                this.mHttpHeaders = HttpHeaders.create();
            }
            this.mHttpHeaders.additionalHttpHeaders(baseUrl, headers);
        }
    }

    public static class IndicatorBuilder {
        private AgentBuilder mAgentBuilder;

        public IndicatorBuilder(AgentBuilder agentBuilder) {
            this.mAgentBuilder = null;
            this.mAgentBuilder = agentBuilder;
        }

        public CommonBuilder useDefaultIndicator(int color) {
            this.mAgentBuilder.mEnableIndicator = true;
            this.mAgentBuilder.mIndicatorColor = color;
            return new CommonBuilder(this.mAgentBuilder);
        }

        public CommonBuilder useDefaultIndicator() {
            this.mAgentBuilder.mEnableIndicator = true;
            return new CommonBuilder(this.mAgentBuilder);
        }

        public CommonBuilder closeIndicator() {
            this.mAgentBuilder.mEnableIndicator = false;
            this.mAgentBuilder.mIndicatorColor = -1;
            this.mAgentBuilder.mHeight = -1;
            return new CommonBuilder(this.mAgentBuilder);
        }

        public CommonBuilder setCustomIndicator(BaseIndicatorView v) {
            if (v != null) {
                this.mAgentBuilder.mEnableIndicator = true;
                this.mAgentBuilder.mBaseIndicatorView = v;
                this.mAgentBuilder.mIsNeedDefaultProgress = false;
            } else {
                this.mAgentBuilder.mEnableIndicator = true;
                this.mAgentBuilder.mIsNeedDefaultProgress = true;
            }
            return new CommonBuilder(this.mAgentBuilder);
        }

        public CommonBuilder useDefaultIndicator(int color, int height_dp) {
            this.mAgentBuilder.mIndicatorColor = color;
            this.mAgentBuilder.mHeight = height_dp;
            return new CommonBuilder(this.mAgentBuilder);
        }
    }

    public static class CommonBuilder {
        private AgentBuilder mAgentBuilder;

        public CommonBuilder(AgentBuilder agentBuilder) {
            this.mAgentBuilder = agentBuilder;
        }

        public CommonBuilder setEventHanadler(IEventHandler iEventHandler) {
            this.mAgentBuilder.mIEventHandler = iEventHandler;
            return this;
        }

        public CommonBuilder closeWebViewClientHelper() {
            this.mAgentBuilder.mWebClientHelper = false;
            return this;
        }

        public CommonBuilder setWebChromeClient(WebChromeClient webChromeClient) {
            this.mAgentBuilder.mWebChromeClient = webChromeClient;
            return this;
        }

        public CommonBuilder setWebViewClient(WebViewClient webChromeClient) {
            this.mAgentBuilder.mWebViewClient = webChromeClient;
            return this;
        }

        public CommonBuilder useMiddlewareWebClient(MiddlewareWebClientBase middleWrareWebClientBase) {
            if (middleWrareWebClientBase != null) {
                if (this.mAgentBuilder.mMiddlewareWebClientBaseHeader != null) {
                    this.mAgentBuilder.mMiddlewareWebClientBaseTail.enq(middleWrareWebClientBase);
                    this.mAgentBuilder.mMiddlewareWebClientBaseTail = middleWrareWebClientBase;
                } else {
                    AgentBuilder agentBuilder = this.mAgentBuilder;
                    agentBuilder.mMiddlewareWebClientBaseHeader = agentBuilder.mMiddlewareWebClientBaseTail = middleWrareWebClientBase;
                }
                return this;
            }
            return this;
        }

        public CommonBuilder useMiddlewareWebChrome(MiddlewareWebChromeBase middlewareWebChromeBase) {
            if (middlewareWebChromeBase != null) {
                if (this.mAgentBuilder.mChromeMiddleWareHeader != null) {
                    this.mAgentBuilder.mChromeMiddleWareTail.enq(middlewareWebChromeBase);
                    this.mAgentBuilder.mChromeMiddleWareTail = middlewareWebChromeBase;
                } else {
                    AgentBuilder agentBuilder = this.mAgentBuilder;
                    agentBuilder.mChromeMiddleWareHeader = agentBuilder.mChromeMiddleWareTail = middlewareWebChromeBase;
                }
                return this;
            }
            return this;
        }

        public CommonBuilder setMainFrameErrorView(View view) {
            this.mAgentBuilder.mErrorView = view;
            return this;
        }

        public CommonBuilder setMainFrameErrorView(int errorLayout, int clickViewId) {
            this.mAgentBuilder.mErrorLayout = errorLayout;
            this.mAgentBuilder.mReloadId = clickViewId;
            return this;
        }

        public CommonBuilder setAgentWebWebSettings(IAgentWebSettings agentWebSettings) {
            this.mAgentBuilder.mAgentWebSettings = agentWebSettings;
            return this;
        }

        public PreAgentWeb createAgentWeb() {
            return this.mAgentBuilder.buildAgentWeb();
        }

        public CommonBuilder addJavascriptInterface(String name, Object o) {
            this.mAgentBuilder.addJavaObject(name, o);
            return this;
        }

        public CommonBuilder setSecurityType(SecurityType type) {
            this.mAgentBuilder.mSecurityType = type;
            return this;
        }

        public CommonBuilder setWebView(WebView webView) {
            this.mAgentBuilder.mWebView = webView;
            return this;
        }

        public CommonBuilder setWebLayout(IWebLayout iWebLayout) {
            this.mAgentBuilder.mWebLayout = iWebLayout;
            return this;
        }

        public CommonBuilder additionalHttpHeader(String baseUrl, String k, String v) {
            this.mAgentBuilder.addHeader(baseUrl, k, v);
            return this;
        }

        public CommonBuilder additionalHttpHeader(String baseUrl, Map<String, String> headers) {
            this.mAgentBuilder.addHeader(baseUrl, headers);
            return this;
        }

        public CommonBuilder setPermissionInterceptor(PermissionInterceptor permissionInterceptor) {
            this.mAgentBuilder.mPermissionInterceptor = permissionInterceptor;
            return this;
        }

        public CommonBuilder setAgentWebUIController(AgentWebUIControllerImplBase agentWebUIController) {
            this.mAgentBuilder.mAgentWebUIController = agentWebUIController;
            return this;
        }

        public CommonBuilder setOpenOtherPageWays(DefaultWebClient.OpenOtherPageWays openOtherPageWays) {
            this.mAgentBuilder.mOpenOtherPage = openOtherPageWays;
            return this;
        }

        public CommonBuilder interceptUnkownUrl() {
            this.mAgentBuilder.mIsInterceptUnkownUrl = true;
            return this;
        }

        public CommonBuilder isInterceptUnkownUrl(boolean isInterceptUnkownUrl) {
            this.mAgentBuilder.mIsInterceptUnkownUrl = isInterceptUnkownUrl;
            return this;
        }
    }

    Activity getActivity() {
        return this.mActivity;
    }

    private static final class PermissionInterceptorWrapper implements PermissionInterceptor {
        private WeakReference<PermissionInterceptor> mWeakReference;

        private PermissionInterceptorWrapper(PermissionInterceptor permissionInterceptor) {
            this.mWeakReference = new WeakReference<>(permissionInterceptor);
        }

        @Override // com.just.agentweb.PermissionInterceptor
        public boolean intercept(String url, String[] permissions, String a) {
            if (this.mWeakReference.get() == null) {
                return false;
            }
            return this.mWeakReference.get().intercept(url, permissions, a);
        }
    }
}
