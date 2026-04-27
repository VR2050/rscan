package com.just.agentweb;

import android.graphics.Bitmap;
import android.net.http.SslError;
import android.os.Message;
import android.view.KeyEvent;
import android.webkit.ClientCertRequest;
import android.webkit.HttpAuthHandler;
import android.webkit.SslErrorHandler;
import android.webkit.WebResourceError;
import android.webkit.WebResourceRequest;
import android.webkit.WebResourceResponse;
import android.webkit.WebView;

/* JADX INFO: loaded from: classes3.dex */
public class WebViewClientDelegate extends android.webkit.WebViewClient {
    private static final String TAG = WebViewClientDelegate.class.getSimpleName();
    private android.webkit.WebViewClient mDelegate;

    WebViewClientDelegate(android.webkit.WebViewClient client) {
        this.mDelegate = client;
    }

    protected android.webkit.WebViewClient getDelegate() {
        return this.mDelegate;
    }

    void setDelegate(android.webkit.WebViewClient delegate) {
        this.mDelegate = delegate;
    }

    @Override // android.webkit.WebViewClient
    @Deprecated
    public boolean shouldOverrideUrlLoading(WebView view, String url) {
        android.webkit.WebViewClient webViewClient = this.mDelegate;
        if (webViewClient != null) {
            return webViewClient.shouldOverrideUrlLoading(view, url);
        }
        return super.shouldOverrideUrlLoading(view, url);
    }

    @Override // android.webkit.WebViewClient
    public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
        android.webkit.WebViewClient webViewClient = this.mDelegate;
        if (webViewClient != null) {
            return webViewClient.shouldOverrideUrlLoading(view, request);
        }
        return super.shouldOverrideUrlLoading(view, request);
    }

    @Override // android.webkit.WebViewClient
    public void onPageStarted(WebView view, String url, Bitmap favicon) {
        android.webkit.WebViewClient webViewClient = this.mDelegate;
        if (webViewClient != null) {
            webViewClient.onPageStarted(view, url, favicon);
        } else {
            super.onPageStarted(view, url, favicon);
        }
    }

    @Override // android.webkit.WebViewClient
    public void onPageFinished(WebView view, String url) {
        android.webkit.WebViewClient webViewClient = this.mDelegate;
        if (webViewClient != null) {
            webViewClient.onPageFinished(view, url);
        } else {
            super.onPageFinished(view, url);
        }
    }

    @Override // android.webkit.WebViewClient
    public void onLoadResource(WebView view, String url) {
        android.webkit.WebViewClient webViewClient = this.mDelegate;
        if (webViewClient != null) {
            webViewClient.onLoadResource(view, url);
        } else {
            super.onLoadResource(view, url);
        }
    }

    @Override // android.webkit.WebViewClient
    public void onPageCommitVisible(WebView view, String url) {
        android.webkit.WebViewClient webViewClient = this.mDelegate;
        if (webViewClient != null) {
            webViewClient.onPageCommitVisible(view, url);
        } else {
            super.onPageCommitVisible(view, url);
        }
    }

    @Override // android.webkit.WebViewClient
    @Deprecated
    public WebResourceResponse shouldInterceptRequest(WebView view, String url) {
        android.webkit.WebViewClient webViewClient = this.mDelegate;
        if (webViewClient != null) {
            return webViewClient.shouldInterceptRequest(view, url);
        }
        return super.shouldInterceptRequest(view, url);
    }

    @Override // android.webkit.WebViewClient
    public WebResourceResponse shouldInterceptRequest(WebView view, WebResourceRequest request) {
        android.webkit.WebViewClient webViewClient = this.mDelegate;
        if (webViewClient != null) {
            return webViewClient.shouldInterceptRequest(view, request);
        }
        return super.shouldInterceptRequest(view, request);
    }

    @Override // android.webkit.WebViewClient
    @Deprecated
    public void onTooManyRedirects(WebView view, Message cancelMsg, Message continueMsg) {
        android.webkit.WebViewClient webViewClient = this.mDelegate;
        if (webViewClient != null) {
            webViewClient.onTooManyRedirects(view, cancelMsg, continueMsg);
        } else {
            super.onTooManyRedirects(view, cancelMsg, continueMsg);
        }
    }

    @Override // android.webkit.WebViewClient
    @Deprecated
    public void onReceivedError(WebView view, int errorCode, String description, String failingUrl) {
        android.webkit.WebViewClient webViewClient = this.mDelegate;
        if (webViewClient != null) {
            webViewClient.onReceivedError(view, errorCode, description, failingUrl);
        } else {
            super.onReceivedError(view, errorCode, description, failingUrl);
        }
    }

    @Override // android.webkit.WebViewClient
    public void onReceivedError(WebView view, WebResourceRequest request, WebResourceError error) {
        android.webkit.WebViewClient webViewClient = this.mDelegate;
        if (webViewClient != null) {
            webViewClient.onReceivedError(view, request, error);
        } else {
            super.onReceivedError(view, request, error);
        }
    }

    @Override // android.webkit.WebViewClient
    public void onReceivedHttpError(WebView view, WebResourceRequest request, WebResourceResponse errorResponse) {
        android.webkit.WebViewClient webViewClient = this.mDelegate;
        if (webViewClient != null) {
            webViewClient.onReceivedHttpError(view, request, errorResponse);
        } else {
            super.onReceivedHttpError(view, request, errorResponse);
        }
    }

    @Override // android.webkit.WebViewClient
    public void onFormResubmission(WebView view, Message dontResend, Message resend) {
        android.webkit.WebViewClient webViewClient = this.mDelegate;
        if (webViewClient != null) {
            webViewClient.onFormResubmission(view, dontResend, resend);
        } else {
            super.onFormResubmission(view, dontResend, resend);
        }
    }

    @Override // android.webkit.WebViewClient
    public void doUpdateVisitedHistory(WebView view, String url, boolean isReload) {
        android.webkit.WebViewClient webViewClient = this.mDelegate;
        if (webViewClient != null) {
            webViewClient.doUpdateVisitedHistory(view, url, isReload);
        } else {
            super.doUpdateVisitedHistory(view, url, isReload);
        }
    }

    @Override // android.webkit.WebViewClient
    public void onReceivedSslError(WebView view, SslErrorHandler handler, SslError error) {
        android.webkit.WebViewClient webViewClient = this.mDelegate;
        if (webViewClient != null) {
            webViewClient.onReceivedSslError(view, handler, error);
        } else {
            super.onReceivedSslError(view, handler, error);
        }
    }

    @Override // android.webkit.WebViewClient
    public void onReceivedClientCertRequest(WebView view, ClientCertRequest request) {
        android.webkit.WebViewClient webViewClient = this.mDelegate;
        if (webViewClient != null) {
            webViewClient.onReceivedClientCertRequest(view, request);
        } else {
            super.onReceivedClientCertRequest(view, request);
        }
    }

    @Override // android.webkit.WebViewClient
    public void onReceivedHttpAuthRequest(WebView view, HttpAuthHandler handler, String host, String realm) {
        android.webkit.WebViewClient webViewClient = this.mDelegate;
        if (webViewClient != null) {
            webViewClient.onReceivedHttpAuthRequest(view, handler, host, realm);
        } else {
            super.onReceivedHttpAuthRequest(view, handler, host, realm);
        }
    }

    @Override // android.webkit.WebViewClient
    public boolean shouldOverrideKeyEvent(WebView view, KeyEvent event) {
        android.webkit.WebViewClient webViewClient = this.mDelegate;
        if (webViewClient != null) {
            return webViewClient.shouldOverrideKeyEvent(view, event);
        }
        return super.shouldOverrideKeyEvent(view, event);
    }

    @Override // android.webkit.WebViewClient
    public void onUnhandledKeyEvent(WebView view, KeyEvent event) {
        android.webkit.WebViewClient webViewClient = this.mDelegate;
        if (webViewClient != null) {
            webViewClient.onUnhandledKeyEvent(view, event);
        } else {
            super.onUnhandledKeyEvent(view, event);
        }
    }

    @Override // android.webkit.WebViewClient
    public void onScaleChanged(WebView view, float oldScale, float newScale) {
        android.webkit.WebViewClient webViewClient = this.mDelegate;
        if (webViewClient != null) {
            webViewClient.onScaleChanged(view, oldScale, newScale);
        } else {
            super.onScaleChanged(view, oldScale, newScale);
        }
    }

    @Override // android.webkit.WebViewClient
    public void onReceivedLoginRequest(WebView view, String realm, String account, String args) {
        android.webkit.WebViewClient webViewClient = this.mDelegate;
        if (webViewClient != null) {
            webViewClient.onReceivedLoginRequest(view, realm, account, args);
        } else {
            super.onReceivedLoginRequest(view, realm, account, args);
        }
    }
}
