package com.just.agentweb;

import android.app.Activity;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewStub;
import android.webkit.WebView;
import android.widget.FrameLayout;

/* JADX INFO: loaded from: classes3.dex */
public class DefaultWebCreator implements WebCreator {
    private static final String TAG = DefaultWebCreator.class.getSimpleName();
    private Activity mActivity;
    private BaseIndicatorSpec mBaseIndicatorSpec;
    private int mColor;
    private FrameLayout mFrameLayout;
    private int mHeight;
    private IWebLayout mIWebLayout;
    private int mIndex;
    private boolean mIsCreated;
    private boolean mIsNeedDefaultProgress;
    private ViewGroup.LayoutParams mLayoutParams;
    private BaseIndicatorView mProgressView;
    private View mTargetProgress;
    private ViewGroup mViewGroup;
    private WebView mWebView;
    private int mWebViewType;

    protected DefaultWebCreator(Activity activity, ViewGroup viewGroup, ViewGroup.LayoutParams lp, int index, int color, int mHeight, WebView webView, IWebLayout webLayout) {
        this.mLayoutParams = null;
        this.mColor = -1;
        this.mIsCreated = false;
        this.mWebView = null;
        this.mFrameLayout = null;
        this.mWebViewType = 1;
        this.mActivity = activity;
        this.mViewGroup = viewGroup;
        this.mIsNeedDefaultProgress = true;
        this.mIndex = index;
        this.mColor = color;
        this.mLayoutParams = lp;
        this.mHeight = mHeight;
        this.mWebView = webView;
        this.mIWebLayout = webLayout;
    }

    protected DefaultWebCreator(Activity activity, ViewGroup viewGroup, ViewGroup.LayoutParams lp, int index, WebView webView, IWebLayout webLayout) {
        this.mLayoutParams = null;
        this.mColor = -1;
        this.mIsCreated = false;
        this.mWebView = null;
        this.mFrameLayout = null;
        this.mWebViewType = 1;
        this.mActivity = activity;
        this.mViewGroup = viewGroup;
        this.mIsNeedDefaultProgress = false;
        this.mIndex = index;
        this.mLayoutParams = lp;
        this.mWebView = webView;
        this.mIWebLayout = webLayout;
    }

    protected DefaultWebCreator(Activity activity, ViewGroup viewGroup, ViewGroup.LayoutParams lp, int index, BaseIndicatorView progressView, WebView webView, IWebLayout webLayout) {
        this.mLayoutParams = null;
        this.mColor = -1;
        this.mIsCreated = false;
        this.mWebView = null;
        this.mFrameLayout = null;
        this.mWebViewType = 1;
        this.mActivity = activity;
        this.mViewGroup = viewGroup;
        this.mIsNeedDefaultProgress = false;
        this.mIndex = index;
        this.mLayoutParams = lp;
        this.mProgressView = progressView;
        this.mWebView = webView;
        this.mIWebLayout = webLayout;
    }

    public void setWebView(WebView webView) {
        this.mWebView = webView;
    }

    public FrameLayout getFrameLayout() {
        return this.mFrameLayout;
    }

    public View getTargetProgress() {
        return this.mTargetProgress;
    }

    public void setTargetProgress(View targetProgress) {
        this.mTargetProgress = targetProgress;
    }

    @Override // com.just.agentweb.WebCreator
    public DefaultWebCreator create() {
        if (this.mIsCreated) {
            return this;
        }
        this.mIsCreated = true;
        ViewGroup mViewGroup = this.mViewGroup;
        if (mViewGroup == null) {
            FrameLayout frameLayout = (FrameLayout) createLayout();
            this.mFrameLayout = frameLayout;
            this.mActivity.setContentView(frameLayout);
        } else if (this.mIndex == -1) {
            FrameLayout frameLayout2 = (FrameLayout) createLayout();
            this.mFrameLayout = frameLayout2;
            mViewGroup.addView(frameLayout2, this.mLayoutParams);
        } else {
            FrameLayout frameLayout3 = (FrameLayout) createLayout();
            this.mFrameLayout = frameLayout3;
            mViewGroup.addView(frameLayout3, this.mIndex, this.mLayoutParams);
        }
        return this;
    }

    @Override // com.just.agentweb.WebCreator
    public WebView getWebView() {
        return this.mWebView;
    }

    @Override // com.just.agentweb.WebCreator
    public FrameLayout getWebParentLayout() {
        return this.mFrameLayout;
    }

    @Override // com.just.agentweb.WebCreator
    public int getWebViewType() {
        return this.mWebViewType;
    }

    private ViewGroup createLayout() {
        WebView webViewWebLayout;
        BaseIndicatorView baseIndicatorView;
        FrameLayout.LayoutParams layoutParamsOfferLayoutParams;
        Activity activity = this.mActivity;
        WebParentLayout webParentLayout = new WebParentLayout(activity);
        webParentLayout.setId(R.id.web_parent_layout_id);
        webParentLayout.setBackgroundColor(-1);
        if (this.mIWebLayout == null) {
            WebView webViewCreateWebView = createWebView();
            this.mWebView = webViewCreateWebView;
            webViewWebLayout = webViewCreateWebView;
        } else {
            webViewWebLayout = webLayout();
        }
        webParentLayout.addView(webViewWebLayout, new FrameLayout.LayoutParams(-1, -1));
        webParentLayout.bindWebView(this.mWebView);
        LogUtils.i(TAG, "  instanceof  AgentWebView:" + (this.mWebView instanceof AgentWebView));
        if (this.mWebView instanceof AgentWebView) {
            this.mWebViewType = 2;
        }
        ViewStub viewStub = new ViewStub(activity);
        viewStub.setId(R.id.mainframe_error_viewsub_id);
        webParentLayout.addView(viewStub, new FrameLayout.LayoutParams(-1, -1));
        boolean z = this.mIsNeedDefaultProgress;
        if (z) {
            WebIndicator webIndicator = new WebIndicator(activity);
            if (this.mHeight > 0) {
                layoutParamsOfferLayoutParams = new FrameLayout.LayoutParams(-2, AgentWebUtils.dp2px(activity, this.mHeight));
            } else {
                layoutParamsOfferLayoutParams = webIndicator.offerLayoutParams();
            }
            int i = this.mColor;
            if (i != -1) {
                webIndicator.setColor(i);
            }
            layoutParamsOfferLayoutParams.gravity = 48;
            this.mBaseIndicatorSpec = webIndicator;
            webParentLayout.addView(webIndicator, layoutParamsOfferLayoutParams);
            webIndicator.setVisibility(8);
        } else if (!z && (baseIndicatorView = this.mProgressView) != null) {
            this.mBaseIndicatorSpec = baseIndicatorView;
            webParentLayout.addView(baseIndicatorView, baseIndicatorView.offerLayoutParams());
            this.mProgressView.setVisibility(8);
        }
        return webParentLayout;
    }

    private View webLayout() {
        WebView webView = this.mIWebLayout.getWebView();
        WebView mWebView = webView;
        if (webView == null) {
            mWebView = createWebView();
            this.mIWebLayout.getLayout().addView(mWebView, -1, -1);
            LogUtils.i(TAG, "add webview");
        } else {
            this.mWebViewType = 3;
        }
        this.mWebView = mWebView;
        return this.mIWebLayout.getLayout();
    }

    private WebView createWebView() {
        if (this.mWebView != null) {
            WebView mWebView = this.mWebView;
            this.mWebViewType = 3;
            return mWebView;
        }
        if (AgentWebConfig.IS_KITKAT_OR_BELOW_KITKAT) {
            WebView mWebView2 = new AgentWebView(this.mActivity);
            this.mWebViewType = 2;
            return mWebView2;
        }
        WebView mWebView3 = new LollipopFixedWebView(this.mActivity);
        this.mWebViewType = 1;
        return mWebView3;
    }

    @Override // com.just.agentweb.IWebIndicator
    public BaseIndicatorSpec offer() {
        return this.mBaseIndicatorSpec;
    }
}
