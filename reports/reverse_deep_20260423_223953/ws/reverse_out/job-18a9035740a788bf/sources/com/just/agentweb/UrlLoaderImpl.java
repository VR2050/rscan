package com.just.agentweb;

import android.os.Handler;
import android.os.Looper;
import android.webkit.WebView;
import java.util.Map;

/* JADX INFO: loaded from: classes3.dex */
public class UrlLoaderImpl implements IUrlLoader {
    public static final String TAG = UrlLoaderImpl.class.getSimpleName();
    private Handler mHandler;
    private HttpHeaders mHttpHeaders;
    private WebView mWebView;

    UrlLoaderImpl(WebView webView, HttpHeaders httpHeaders) {
        this.mHandler = null;
        this.mWebView = webView;
        if (webView == null) {
            new NullPointerException("webview cannot be null .");
        }
        this.mHttpHeaders = httpHeaders;
        if (httpHeaders == null) {
            this.mHttpHeaders = HttpHeaders.create();
        }
        this.mHandler = new Handler(Looper.getMainLooper());
    }

    private void safeLoadUrl(final String url) {
        this.mHandler.post(new Runnable() { // from class: com.just.agentweb.UrlLoaderImpl.1
            @Override // java.lang.Runnable
            public void run() {
                UrlLoaderImpl.this.loadUrl(url);
            }
        });
    }

    private void safeReload() {
        this.mHandler.post(new Runnable() { // from class: com.just.agentweb.UrlLoaderImpl.2
            @Override // java.lang.Runnable
            public void run() {
                UrlLoaderImpl.this.reload();
            }
        });
    }

    @Override // com.just.agentweb.IUrlLoader
    public void loadUrl(String url) {
        loadUrl(url, this.mHttpHeaders.getHeaders(url));
    }

    @Override // com.just.agentweb.IUrlLoader
    public void loadUrl(final String url, final Map<String, String> headers) {
        if (!AgentWebUtils.isUIThread()) {
            AgentWebUtils.runInUiThread(new Runnable() { // from class: com.just.agentweb.UrlLoaderImpl.3
                @Override // java.lang.Runnable
                public void run() {
                    UrlLoaderImpl.this.loadUrl(url, headers);
                }
            });
            return;
        }
        LogUtils.i(TAG, "loadUrl:" + url + " headers:" + headers);
        if (headers == null || headers.isEmpty()) {
            this.mWebView.loadUrl(url);
        } else {
            this.mWebView.loadUrl(url, headers);
        }
    }

    @Override // com.just.agentweb.IUrlLoader
    public void reload() {
        if (!AgentWebUtils.isUIThread()) {
            this.mHandler.post(new Runnable() { // from class: com.just.agentweb.UrlLoaderImpl.4
                @Override // java.lang.Runnable
                public void run() {
                    UrlLoaderImpl.this.reload();
                }
            });
        } else {
            this.mWebView.reload();
        }
    }

    @Override // com.just.agentweb.IUrlLoader
    public void loadData(final String data, final String mimeType, final String encoding) {
        if (!AgentWebUtils.isUIThread()) {
            this.mHandler.post(new Runnable() { // from class: com.just.agentweb.UrlLoaderImpl.5
                @Override // java.lang.Runnable
                public void run() {
                    UrlLoaderImpl.this.loadData(data, mimeType, encoding);
                }
            });
        } else {
            this.mWebView.loadData(data, mimeType, encoding);
        }
    }

    @Override // com.just.agentweb.IUrlLoader
    public void stopLoading() {
        if (!AgentWebUtils.isUIThread()) {
            this.mHandler.post(new Runnable() { // from class: com.just.agentweb.UrlLoaderImpl.6
                @Override // java.lang.Runnable
                public void run() {
                    UrlLoaderImpl.this.stopLoading();
                }
            });
        } else {
            this.mWebView.stopLoading();
        }
    }

    @Override // com.just.agentweb.IUrlLoader
    public void loadDataWithBaseURL(final String baseUrl, final String data, final String mimeType, final String encoding, final String historyUrl) {
        if (!AgentWebUtils.isUIThread()) {
            this.mHandler.post(new Runnable() { // from class: com.just.agentweb.UrlLoaderImpl.7
                @Override // java.lang.Runnable
                public void run() {
                    UrlLoaderImpl.this.loadDataWithBaseURL(baseUrl, data, mimeType, encoding, historyUrl);
                }
            });
        } else {
            this.mWebView.loadDataWithBaseURL(baseUrl, data, mimeType, encoding, historyUrl);
        }
    }

    @Override // com.just.agentweb.IUrlLoader
    public void postUrl(final String url, final byte[] postData) {
        if (!AgentWebUtils.isUIThread()) {
            this.mHandler.post(new Runnable() { // from class: com.just.agentweb.UrlLoaderImpl.8
                @Override // java.lang.Runnable
                public void run() {
                    UrlLoaderImpl.this.postUrl(url, postData);
                }
            });
        } else {
            this.mWebView.postUrl(url, postData);
        }
    }

    @Override // com.just.agentweb.IUrlLoader
    public HttpHeaders getHttpHeaders() {
        HttpHeaders httpHeaders = this.mHttpHeaders;
        if (httpHeaders != null) {
            return httpHeaders;
        }
        HttpHeaders httpHeadersCreate = HttpHeaders.create();
        this.mHttpHeaders = httpHeadersCreate;
        return httpHeadersCreate;
    }
}
