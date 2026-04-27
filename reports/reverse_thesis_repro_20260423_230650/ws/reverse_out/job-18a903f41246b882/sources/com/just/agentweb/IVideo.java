package com.just.agentweb;

import android.view.View;
import android.webkit.WebChromeClient;

/* JADX INFO: loaded from: classes3.dex */
public interface IVideo {
    boolean isVideoState();

    void onHideCustomView();

    void onShowCustomView(View view, WebChromeClient.CustomViewCallback customViewCallback);
}
