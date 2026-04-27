package com.just.agentweb;

import android.app.Activity;
import android.os.Build;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.webkit.WebChromeClient;
import android.webkit.WebView;
import android.widget.FrameLayout;
import androidx.core.util.Pair;
import java.util.HashSet;
import java.util.Set;

/* JADX INFO: loaded from: classes3.dex */
public class VideoImpl implements IVideo, EventInterceptor {
    private static final String TAG = VideoImpl.class.getSimpleName();
    private Activity mActivity;
    private WebChromeClient.CustomViewCallback mCallback;
    private Set<Pair<Integer, Integer>> mFlags;
    private WebView mWebView;
    private View mMoiveView = null;
    private ViewGroup mMoiveParentView = null;

    public VideoImpl(Activity mActivity, WebView webView) {
        this.mFlags = null;
        this.mActivity = mActivity;
        this.mWebView = webView;
        this.mFlags = new HashSet();
    }

    @Override // com.just.agentweb.IVideo
    public void onShowCustomView(View view, WebChromeClient.CustomViewCallback callback) {
        Activity mActivity = this.mActivity;
        if (mActivity == null || mActivity.isFinishing()) {
            return;
        }
        mActivity.setRequestedOrientation(0);
        Window mWindow = mActivity.getWindow();
        if ((mWindow.getAttributes().flags & 128) == 0) {
            Pair<Integer, Integer> mPair = new Pair<>(128, 0);
            mWindow.setFlags(128, 128);
            this.mFlags.add(mPair);
        }
        if (Build.VERSION.SDK_INT >= 11 && (mWindow.getAttributes().flags & 16777216) == 0) {
            Pair<Integer, Integer> mPair2 = new Pair<>(16777216, 0);
            mWindow.setFlags(16777216, 16777216);
            this.mFlags.add(mPair2);
        }
        if (this.mMoiveView != null) {
            callback.onCustomViewHidden();
            return;
        }
        WebView webView = this.mWebView;
        if (webView != null) {
            webView.setVisibility(8);
        }
        if (this.mMoiveParentView == null) {
            FrameLayout mDecorView = (FrameLayout) mActivity.getWindow().getDecorView();
            FrameLayout frameLayout = new FrameLayout(mActivity);
            this.mMoiveParentView = frameLayout;
            frameLayout.setBackgroundColor(-16777216);
            mDecorView.addView(this.mMoiveParentView);
        }
        this.mCallback = callback;
        ViewGroup viewGroup = this.mMoiveParentView;
        this.mMoiveView = view;
        viewGroup.addView(view);
        this.mMoiveParentView.setVisibility(0);
    }

    @Override // com.just.agentweb.IVideo
    public void onHideCustomView() {
        View view;
        if (this.mMoiveView == null) {
            return;
        }
        Activity activity = this.mActivity;
        if (activity != null && activity.getRequestedOrientation() != 1) {
            this.mActivity.setRequestedOrientation(1);
        }
        if (!this.mFlags.isEmpty()) {
            for (Pair<Integer, Integer> mPair : this.mFlags) {
                this.mActivity.getWindow().setFlags(mPair.second.intValue(), mPair.first.intValue());
            }
            this.mFlags.clear();
        }
        this.mMoiveView.setVisibility(8);
        ViewGroup viewGroup = this.mMoiveParentView;
        if (viewGroup != null && (view = this.mMoiveView) != null) {
            viewGroup.removeView(view);
        }
        ViewGroup viewGroup2 = this.mMoiveParentView;
        if (viewGroup2 != null) {
            viewGroup2.setVisibility(8);
        }
        WebChromeClient.CustomViewCallback customViewCallback = this.mCallback;
        if (customViewCallback != null) {
            customViewCallback.onCustomViewHidden();
        }
        this.mMoiveView = null;
        WebView webView = this.mWebView;
        if (webView != null) {
            webView.setVisibility(0);
        }
    }

    @Override // com.just.agentweb.IVideo
    public boolean isVideoState() {
        return this.mMoiveView != null;
    }

    @Override // com.just.agentweb.EventInterceptor
    public boolean event() {
        if (isVideoState()) {
            onHideCustomView();
            return true;
        }
        return false;
    }
}
