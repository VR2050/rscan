package com.just.agentweb;

import android.view.KeyEvent;
import android.webkit.WebView;

/* JADX INFO: loaded from: classes3.dex */
public class EventHandlerImpl implements IEventHandler {
    private EventInterceptor mEventInterceptor;
    private WebView mWebView;

    public static final EventHandlerImpl getInstantce(WebView view, EventInterceptor eventInterceptor) {
        return new EventHandlerImpl(view, eventInterceptor);
    }

    public EventHandlerImpl(WebView webView, EventInterceptor eventInterceptor) {
        this.mWebView = webView;
        this.mEventInterceptor = eventInterceptor;
    }

    @Override // com.just.agentweb.IEventHandler
    public boolean onKeyDown(int keyCode, KeyEvent event) {
        if (keyCode == 4) {
            return back();
        }
        return false;
    }

    @Override // com.just.agentweb.IEventHandler
    public boolean back() {
        EventInterceptor eventInterceptor = this.mEventInterceptor;
        if (eventInterceptor != null && eventInterceptor.event()) {
            return true;
        }
        WebView webView = this.mWebView;
        if (webView != null && webView.canGoBack()) {
            this.mWebView.goBack();
            return true;
        }
        return false;
    }
}
