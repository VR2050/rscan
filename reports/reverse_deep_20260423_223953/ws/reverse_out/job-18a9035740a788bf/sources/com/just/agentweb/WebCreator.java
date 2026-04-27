package com.just.agentweb;

import android.webkit.WebView;
import android.widget.FrameLayout;

/* JADX INFO: loaded from: classes3.dex */
public interface WebCreator extends IWebIndicator {
    WebCreator create();

    FrameLayout getWebParentLayout();

    WebView getWebView();

    int getWebViewType();
}
