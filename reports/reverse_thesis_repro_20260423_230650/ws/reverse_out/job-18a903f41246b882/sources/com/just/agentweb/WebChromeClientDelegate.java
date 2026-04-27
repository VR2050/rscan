package com.just.agentweb;

import android.graphics.Bitmap;
import android.net.Uri;
import android.os.Message;
import android.view.View;
import android.webkit.ConsoleMessage;
import android.webkit.GeolocationPermissions;
import android.webkit.JsPromptResult;
import android.webkit.JsResult;
import android.webkit.PermissionRequest;
import android.webkit.ValueCallback;
import android.webkit.WebChromeClient;
import android.webkit.WebStorage;
import android.webkit.WebView;
import java.lang.reflect.Method;

/* JADX INFO: loaded from: classes3.dex */
public class WebChromeClientDelegate extends android.webkit.WebChromeClient {
    private android.webkit.WebChromeClient mDelegate;

    protected android.webkit.WebChromeClient getDelegate() {
        return this.mDelegate;
    }

    public WebChromeClientDelegate(android.webkit.WebChromeClient webChromeClient) {
        this.mDelegate = webChromeClient;
    }

    void setDelegate(android.webkit.WebChromeClient delegate) {
        this.mDelegate = delegate;
    }

    @Override // android.webkit.WebChromeClient
    public void onProgressChanged(WebView view, int newProgress) {
        super.onProgressChanged(view, newProgress);
        android.webkit.WebChromeClient webChromeClient = this.mDelegate;
        if (webChromeClient != null) {
            webChromeClient.onProgressChanged(view, newProgress);
        }
    }

    @Override // android.webkit.WebChromeClient
    public void onReceivedTitle(WebView view, String title) {
        android.webkit.WebChromeClient webChromeClient = this.mDelegate;
        if (webChromeClient != null) {
            webChromeClient.onReceivedTitle(view, title);
        } else {
            super.onReceivedTitle(view, title);
        }
    }

    @Override // android.webkit.WebChromeClient
    public void onReceivedIcon(WebView view, Bitmap icon) {
        android.webkit.WebChromeClient webChromeClient = this.mDelegate;
        if (webChromeClient != null) {
            webChromeClient.onReceivedIcon(view, icon);
        } else {
            super.onReceivedIcon(view, icon);
        }
    }

    @Override // android.webkit.WebChromeClient
    public void onReceivedTouchIconUrl(WebView view, String url, boolean precomposed) {
        android.webkit.WebChromeClient webChromeClient = this.mDelegate;
        if (webChromeClient != null) {
            webChromeClient.onReceivedTouchIconUrl(view, url, precomposed);
        } else {
            super.onReceivedTouchIconUrl(view, url, precomposed);
        }
    }

    @Override // android.webkit.WebChromeClient
    public void onShowCustomView(View view, WebChromeClient.CustomViewCallback callback) {
        android.webkit.WebChromeClient webChromeClient = this.mDelegate;
        if (webChromeClient != null) {
            webChromeClient.onShowCustomView(view, callback);
        } else {
            super.onShowCustomView(view, callback);
        }
    }

    @Override // android.webkit.WebChromeClient
    public void onShowCustomView(View view, int requestedOrientation, WebChromeClient.CustomViewCallback callback) {
        android.webkit.WebChromeClient webChromeClient = this.mDelegate;
        if (webChromeClient != null) {
            webChromeClient.onShowCustomView(view, requestedOrientation, callback);
        } else {
            super.onShowCustomView(view, requestedOrientation, callback);
        }
    }

    @Override // android.webkit.WebChromeClient
    public void onHideCustomView() {
        android.webkit.WebChromeClient webChromeClient = this.mDelegate;
        if (webChromeClient != null) {
            webChromeClient.onHideCustomView();
        } else {
            super.onHideCustomView();
        }
    }

    @Override // android.webkit.WebChromeClient
    public boolean onCreateWindow(WebView view, boolean isDialog, boolean isUserGesture, Message resultMsg) {
        android.webkit.WebChromeClient webChromeClient = this.mDelegate;
        if (webChromeClient != null) {
            return webChromeClient.onCreateWindow(view, isDialog, isUserGesture, resultMsg);
        }
        return super.onCreateWindow(view, isDialog, isUserGesture, resultMsg);
    }

    @Override // android.webkit.WebChromeClient
    public void onRequestFocus(WebView view) {
        android.webkit.WebChromeClient webChromeClient = this.mDelegate;
        if (webChromeClient != null) {
            webChromeClient.onRequestFocus(view);
        } else {
            super.onRequestFocus(view);
        }
    }

    @Override // android.webkit.WebChromeClient
    public void onCloseWindow(WebView window) {
        android.webkit.WebChromeClient webChromeClient = this.mDelegate;
        if (webChromeClient != null) {
            webChromeClient.onCloseWindow(window);
        } else {
            super.onCloseWindow(window);
        }
    }

    @Override // android.webkit.WebChromeClient
    public boolean onJsAlert(WebView view, String url, String message, JsResult result) {
        android.webkit.WebChromeClient webChromeClient = this.mDelegate;
        if (webChromeClient != null) {
            return webChromeClient.onJsAlert(view, url, message, result);
        }
        return super.onJsAlert(view, url, message, result);
    }

    @Override // android.webkit.WebChromeClient
    public boolean onJsConfirm(WebView view, String url, String message, JsResult result) {
        android.webkit.WebChromeClient webChromeClient = this.mDelegate;
        if (webChromeClient != null) {
            return webChromeClient.onJsConfirm(view, url, message, result);
        }
        return super.onJsConfirm(view, url, message, result);
    }

    @Override // android.webkit.WebChromeClient
    public boolean onJsPrompt(WebView view, String url, String message, String defaultValue, JsPromptResult result) {
        android.webkit.WebChromeClient webChromeClient = this.mDelegate;
        if (webChromeClient != null) {
            return webChromeClient.onJsPrompt(view, url, message, defaultValue, result);
        }
        return super.onJsPrompt(view, url, message, defaultValue, result);
    }

    @Override // android.webkit.WebChromeClient
    public boolean onJsBeforeUnload(WebView view, String url, String message, JsResult result) {
        android.webkit.WebChromeClient webChromeClient = this.mDelegate;
        if (webChromeClient != null) {
            return webChromeClient.onJsBeforeUnload(view, url, message, result);
        }
        return super.onJsBeforeUnload(view, url, message, result);
    }

    @Override // android.webkit.WebChromeClient
    @Deprecated
    public void onExceededDatabaseQuota(String url, String databaseIdentifier, long quota, long estimatedDatabaseSize, long totalQuota, WebStorage.QuotaUpdater quotaUpdater) {
        android.webkit.WebChromeClient webChromeClient = this.mDelegate;
        if (webChromeClient != null) {
            webChromeClient.onExceededDatabaseQuota(url, databaseIdentifier, quota, estimatedDatabaseSize, totalQuota, quotaUpdater);
        } else {
            super.onExceededDatabaseQuota(url, databaseIdentifier, quota, estimatedDatabaseSize, totalQuota, quotaUpdater);
        }
    }

    @Deprecated
    public void onReachedMaxAppCacheSize(long requiredStorage, long quota, WebStorage.QuotaUpdater quotaUpdater) {
        android.webkit.WebChromeClient webChromeClient = this.mDelegate;
        if (webChromeClient != null) {
            webChromeClient.onReachedMaxAppCacheSize(requiredStorage, quota, quotaUpdater);
        } else {
            super.onReachedMaxAppCacheSize(requiredStorage, quota, quotaUpdater);
        }
    }

    @Override // android.webkit.WebChromeClient
    public void onGeolocationPermissionsShowPrompt(String origin, GeolocationPermissions.Callback callback) {
        android.webkit.WebChromeClient webChromeClient = this.mDelegate;
        if (webChromeClient != null) {
            webChromeClient.onGeolocationPermissionsShowPrompt(origin, callback);
        } else {
            super.onGeolocationPermissionsShowPrompt(origin, callback);
        }
    }

    @Override // android.webkit.WebChromeClient
    public void onGeolocationPermissionsHidePrompt() {
        android.webkit.WebChromeClient webChromeClient = this.mDelegate;
        if (webChromeClient != null) {
            webChromeClient.onGeolocationPermissionsHidePrompt();
        } else {
            super.onGeolocationPermissionsHidePrompt();
        }
    }

    @Override // android.webkit.WebChromeClient
    public void onPermissionRequest(PermissionRequest request) {
        android.webkit.WebChromeClient webChromeClient = this.mDelegate;
        if (webChromeClient != null) {
            webChromeClient.onPermissionRequest(request);
        } else {
            super.onPermissionRequest(request);
        }
    }

    @Override // android.webkit.WebChromeClient
    public void onPermissionRequestCanceled(PermissionRequest request) {
        android.webkit.WebChromeClient webChromeClient = this.mDelegate;
        if (webChromeClient != null) {
            webChromeClient.onPermissionRequestCanceled(request);
        } else {
            super.onPermissionRequestCanceled(request);
        }
    }

    @Override // android.webkit.WebChromeClient
    public boolean onJsTimeout() {
        android.webkit.WebChromeClient webChromeClient = this.mDelegate;
        if (webChromeClient != null) {
            return webChromeClient.onJsTimeout();
        }
        return super.onJsTimeout();
    }

    @Override // android.webkit.WebChromeClient
    @Deprecated
    public void onConsoleMessage(String message, int lineNumber, String sourceID) {
        android.webkit.WebChromeClient webChromeClient = this.mDelegate;
        if (webChromeClient != null) {
            webChromeClient.onConsoleMessage(message, lineNumber, sourceID);
        } else {
            super.onConsoleMessage(message, lineNumber, sourceID);
        }
    }

    @Override // android.webkit.WebChromeClient
    public boolean onConsoleMessage(ConsoleMessage consoleMessage) {
        android.webkit.WebChromeClient webChromeClient = this.mDelegate;
        if (webChromeClient != null) {
            return webChromeClient.onConsoleMessage(consoleMessage);
        }
        return super.onConsoleMessage(consoleMessage);
    }

    @Override // android.webkit.WebChromeClient
    public Bitmap getDefaultVideoPoster() {
        android.webkit.WebChromeClient webChromeClient = this.mDelegate;
        if (webChromeClient != null) {
            return webChromeClient.getDefaultVideoPoster();
        }
        return super.getDefaultVideoPoster();
    }

    @Override // android.webkit.WebChromeClient
    public View getVideoLoadingProgressView() {
        android.webkit.WebChromeClient webChromeClient = this.mDelegate;
        if (webChromeClient != null) {
            return webChromeClient.getVideoLoadingProgressView();
        }
        return super.getVideoLoadingProgressView();
    }

    @Override // android.webkit.WebChromeClient
    public void getVisitedHistory(ValueCallback<String[]> callback) {
        android.webkit.WebChromeClient webChromeClient = this.mDelegate;
        if (webChromeClient != null) {
            webChromeClient.getVisitedHistory(callback);
        } else {
            super.getVisitedHistory(callback);
        }
    }

    @Override // android.webkit.WebChromeClient
    public boolean onShowFileChooser(WebView webView, ValueCallback<Uri[]> filePathCallback, WebChromeClient.FileChooserParams fileChooserParams) {
        android.webkit.WebChromeClient webChromeClient = this.mDelegate;
        if (webChromeClient != null) {
            return webChromeClient.onShowFileChooser(webView, filePathCallback, fileChooserParams);
        }
        return super.onShowFileChooser(webView, filePathCallback, fileChooserParams);
    }

    public void openFileChooser(ValueCallback<Uri> uploadFile, String acceptType, String capture) {
        commonRefect(this.mDelegate, "openFileChooser", new Object[]{uploadFile, acceptType, capture}, ValueCallback.class, String.class, String.class);
    }

    public void openFileChooser(ValueCallback<Uri> valueCallback) {
        commonRefect(this.mDelegate, "openFileChooser", new Object[]{valueCallback}, ValueCallback.class);
    }

    public void openFileChooser(ValueCallback valueCallback, String acceptType) {
        commonRefect(this.mDelegate, "openFileChooser", new Object[]{valueCallback, acceptType}, ValueCallback.class, String.class);
    }

    private void commonRefect(android.webkit.WebChromeClient o, String mothed, Object[] os, Class... clazzs) {
        if (o == null) {
            return;
        }
        try {
            Class<?> clazz = o.getClass();
            Method mMethod = clazz.getMethod(mothed, clazzs);
            mMethod.invoke(o, os);
        } catch (Exception ignore) {
            if (LogUtils.isDebug()) {
                ignore.printStackTrace();
            }
        }
    }
}
