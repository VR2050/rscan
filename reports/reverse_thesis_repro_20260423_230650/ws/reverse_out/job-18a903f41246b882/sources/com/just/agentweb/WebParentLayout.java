package com.just.agentweb;

import android.app.Activity;
import android.content.Context;
import android.util.AttributeSet;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewStub;
import android.webkit.WebView;
import android.widget.FrameLayout;

/* JADX INFO: loaded from: classes3.dex */
public class WebParentLayout extends FrameLayout implements Provider<AbsAgentWebUIController> {
    private static final String TAG = WebParentLayout.class.getSimpleName();
    private AbsAgentWebUIController mAgentWebUIController;
    private int mClickId;
    private FrameLayout mErrorLayout;
    private int mErrorLayoutRes;
    private View mErrorView;
    private WebView mWebView;

    WebParentLayout(Context context) {
        this(context, null);
        LogUtils.i(TAG, "WebParentLayout");
    }

    WebParentLayout(Context context, AttributeSet attrs) {
        this(context, attrs, -1);
    }

    WebParentLayout(Context context, AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
        this.mAgentWebUIController = null;
        this.mClickId = -1;
        this.mErrorLayout = null;
        if (!(context instanceof Activity)) {
            throw new IllegalArgumentException("WebParentLayout context must be activity or activity sub class .");
        }
        this.mErrorLayoutRes = R.layout.agentweb_error_page;
    }

    void bindController(AbsAgentWebUIController agentWebUIController) {
        this.mAgentWebUIController = agentWebUIController;
        agentWebUIController.bindWebParent(this, (Activity) getContext());
    }

    void showPageMainFrameError() {
        View clickView;
        View container = this.mErrorLayout;
        if (container != null) {
            container.setVisibility(0);
        } else {
            createErrorLayout();
            container = this.mErrorLayout;
        }
        int i = this.mClickId;
        if (i != -1 && (clickView = container.findViewById(i)) != null) {
            clickView.setClickable(true);
        } else {
            container.setClickable(true);
        }
    }

    private void createErrorLayout() {
        final FrameLayout mFrameLayout = new FrameLayout(getContext());
        mFrameLayout.setBackgroundColor(-1);
        mFrameLayout.setId(R.id.mainframe_error_container_id);
        View view = this.mErrorView;
        if (view == null) {
            LayoutInflater mLayoutInflater = LayoutInflater.from(getContext());
            LogUtils.i(TAG, "mErrorLayoutRes:" + this.mErrorLayoutRes);
            mLayoutInflater.inflate(this.mErrorLayoutRes, (ViewGroup) mFrameLayout, true);
        } else {
            mFrameLayout.addView(view);
        }
        View mViewStub = (ViewStub) findViewById(R.id.mainframe_error_viewsub_id);
        int index = indexOfChild(mViewStub);
        removeViewInLayout(mViewStub);
        ViewGroup.LayoutParams layoutParams = getLayoutParams();
        if (layoutParams != null) {
            this.mErrorLayout = mFrameLayout;
            addView(mFrameLayout, index, layoutParams);
        } else {
            this.mErrorLayout = mFrameLayout;
            addView(mFrameLayout, index);
        }
        mFrameLayout.setVisibility(0);
        int i = this.mClickId;
        if (i != -1) {
            final View clickView = mFrameLayout.findViewById(i);
            if (clickView != null) {
                clickView.setOnClickListener(new View.OnClickListener() { // from class: com.just.agentweb.WebParentLayout.1
                    @Override // android.view.View.OnClickListener
                    public void onClick(View v) {
                        if (WebParentLayout.this.getWebView() != null) {
                            clickView.setClickable(false);
                            WebParentLayout.this.getWebView().reload();
                        }
                    }
                });
                return;
            } else if (LogUtils.isDebug()) {
                LogUtils.e(TAG, "ClickView is null , cannot bind accurate view to refresh or reload .");
            }
        }
        mFrameLayout.setOnClickListener(new View.OnClickListener() { // from class: com.just.agentweb.WebParentLayout.2
            @Override // android.view.View.OnClickListener
            public void onClick(View v) {
                if (WebParentLayout.this.getWebView() != null) {
                    mFrameLayout.setClickable(false);
                    WebParentLayout.this.getWebView().reload();
                }
            }
        });
    }

    void hideErrorLayout() {
        View mView = findViewById(R.id.mainframe_error_container_id);
        if (mView != null) {
            mView.setVisibility(8);
        }
    }

    void setErrorView(View errorView) {
        this.mErrorView = errorView;
    }

    void setErrorLayoutRes(int resLayout, int id) {
        this.mClickId = id;
        if (id <= 0) {
            this.mClickId = -1;
        }
        this.mErrorLayoutRes = resLayout;
        if (resLayout <= 0) {
            this.mErrorLayoutRes = R.layout.agentweb_error_page;
        }
    }

    /* JADX WARN: Can't rename method to resolve collision */
    @Override // com.just.agentweb.Provider
    public AbsAgentWebUIController provide() {
        return this.mAgentWebUIController;
    }

    void bindWebView(WebView view) {
        if (this.mWebView == null) {
            this.mWebView = view;
        }
    }

    WebView getWebView() {
        return this.mWebView;
    }
}
