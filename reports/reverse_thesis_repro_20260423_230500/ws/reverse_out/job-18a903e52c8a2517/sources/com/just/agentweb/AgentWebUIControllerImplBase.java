package com.just.agentweb;

import android.app.Activity;
import android.net.http.SslError;
import android.os.Handler;
import android.webkit.JsPromptResult;
import android.webkit.JsResult;
import android.webkit.PermissionRequest;
import android.webkit.SslErrorHandler;
import android.webkit.WebView;

/* JADX INFO: loaded from: classes3.dex */
public class AgentWebUIControllerImplBase extends AbsAgentWebUIController {
    public static AbsAgentWebUIController build() {
        return new AgentWebUIControllerImplBase();
    }

    @Override // com.just.agentweb.AbsAgentWebUIController
    public void onJsAlert(WebView view, String url, String message) {
        getDelegate().onJsAlert(view, url, message);
    }

    @Override // com.just.agentweb.AbsAgentWebUIController
    public void onOpenPagePrompt(WebView view, String url, Handler.Callback callback) {
        getDelegate().onOpenPagePrompt(view, url, callback);
    }

    @Override // com.just.agentweb.AbsAgentWebUIController
    public void onJsConfirm(WebView view, String url, String message, JsResult jsResult) {
        getDelegate().onJsConfirm(view, url, message, jsResult);
    }

    @Override // com.just.agentweb.AbsAgentWebUIController
    public void onSelectItemsPrompt(WebView view, String url, String[] ways, Handler.Callback callback) {
        getDelegate().onSelectItemsPrompt(view, url, ways, callback);
    }

    @Override // com.just.agentweb.AbsAgentWebUIController
    public void onForceDownloadAlert(String url, Handler.Callback callback) {
        getDelegate().onForceDownloadAlert(url, callback);
    }

    @Override // com.just.agentweb.AbsAgentWebUIController
    public void onJsPrompt(WebView view, String url, String message, String defaultValue, JsPromptResult jsPromptResult) {
        getDelegate().onJsPrompt(view, url, message, defaultValue, jsPromptResult);
    }

    @Override // com.just.agentweb.AbsAgentWebUIController
    public void onMainFrameError(WebView view, int errorCode, String description, String failingUrl) {
        getDelegate().onMainFrameError(view, errorCode, description, failingUrl);
    }

    @Override // com.just.agentweb.AbsAgentWebUIController
    public void onShowMainFrame() {
        getDelegate().onShowMainFrame();
    }

    @Override // com.just.agentweb.AbsAgentWebUIController
    public void onLoading(String msg) {
        getDelegate().onLoading(msg);
    }

    @Override // com.just.agentweb.AbsAgentWebUIController
    public void onCancelLoading() {
        getDelegate().onCancelLoading();
    }

    @Override // com.just.agentweb.AbsAgentWebUIController
    public void onShowMessage(String message, String from) {
        getDelegate().onShowMessage(message, from);
    }

    @Override // com.just.agentweb.AbsAgentWebUIController
    public void onPermissionsDeny(String[] permissions, String permissionType, String action) {
        getDelegate().onPermissionsDeny(permissions, permissionType, action);
    }

    @Override // com.just.agentweb.AbsAgentWebUIController
    public void onShowSslCertificateErrorDialog(WebView view, SslErrorHandler handler, SslError error) {
        getDelegate().onShowSslCertificateErrorDialog(view, handler, error);
    }

    @Override // com.just.agentweb.AbsAgentWebUIController
    public void onPermissionRequest(PermissionRequest request) {
        getDelegate().onPermissionRequest(request);
    }

    @Override // com.just.agentweb.AbsAgentWebUIController
    protected void bindSupportWebParent(WebParentLayout webParentLayout, Activity activity) {
        getDelegate().bindSupportWebParent(webParentLayout, activity);
    }
}
