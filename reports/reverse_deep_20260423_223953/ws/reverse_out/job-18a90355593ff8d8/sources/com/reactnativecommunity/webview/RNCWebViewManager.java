package com.reactnativecommunity.webview;

import android.view.View;
import com.facebook.react.bridge.ReadableArray;
import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.uimanager.B0;
import com.facebook.react.uimanager.Q0;
import com.facebook.react.uimanager.ViewGroupManager;
import d1.AbstractC0508d;
import java.util.Map;
import org.json.JSONException;
import org.json.JSONObject;
import u1.InterfaceC0703a;

/* JADX INFO: loaded from: classes.dex */
@InterfaceC0703a(name = "RNCWebView")
public class RNCWebViewManager extends ViewGroupManager<q> implements T1.o {
    private final Q0 mDelegate = new T1.n(this);
    private final l mRNCWebViewManagerImpl = new l(true);

    @Override // com.facebook.react.uimanager.ViewManager
    public Map<String, Integer> getCommandsMap() {
        return this.mRNCWebViewManagerImpl.g();
    }

    @Override // com.facebook.react.uimanager.ViewManager
    protected Q0 getDelegate() {
        return this.mDelegate;
    }

    @Override // com.facebook.react.uimanager.BaseViewManager, com.facebook.react.uimanager.ViewManager
    public Map<String, Object> getExportedCustomDirectEventTypeConstants() {
        Map<String, Object> exportedCustomDirectEventTypeConstants = super.getExportedCustomDirectEventTypeConstants();
        if (exportedCustomDirectEventTypeConstants == null) {
            exportedCustomDirectEventTypeConstants = AbstractC0508d.b();
        }
        exportedCustomDirectEventTypeConstants.put("topLoadingStart", AbstractC0508d.d("registrationName", "onLoadingStart"));
        exportedCustomDirectEventTypeConstants.put("topLoadingFinish", AbstractC0508d.d("registrationName", "onLoadingFinish"));
        exportedCustomDirectEventTypeConstants.put("topLoadingError", AbstractC0508d.d("registrationName", "onLoadingError"));
        exportedCustomDirectEventTypeConstants.put("topMessage", AbstractC0508d.d("registrationName", "onMessage"));
        exportedCustomDirectEventTypeConstants.put("topLoadingProgress", AbstractC0508d.d("registrationName", "onLoadingProgress"));
        exportedCustomDirectEventTypeConstants.put("topShouldStartLoadWithRequest", AbstractC0508d.d("registrationName", "onShouldStartLoadWithRequest"));
        exportedCustomDirectEventTypeConstants.put(com.facebook.react.views.scroll.l.b(com.facebook.react.views.scroll.l.f8017e), AbstractC0508d.d("registrationName", "onScroll"));
        exportedCustomDirectEventTypeConstants.put("topHttpError", AbstractC0508d.d("registrationName", "onHttpError"));
        exportedCustomDirectEventTypeConstants.put("topRenderProcessGone", AbstractC0508d.d("registrationName", "onRenderProcessGone"));
        exportedCustomDirectEventTypeConstants.put("topCustomMenuSelection", AbstractC0508d.d("registrationName", "onCustomMenuSelection"));
        exportedCustomDirectEventTypeConstants.put("topOpenWindow", AbstractC0508d.d("registrationName", "onOpenWindow"));
        return exportedCustomDirectEventTypeConstants;
    }

    @Override // com.facebook.react.uimanager.ViewManager, com.facebook.react.bridge.NativeModule
    public String getName() {
        return "RNCWebView";
    }

    @Override // com.facebook.react.uimanager.ViewGroupManager, com.facebook.react.uimanager.N
    public /* bridge */ /* synthetic */ void removeAllViews(View view) {
        super.removeAllViews(view);
    }

    @Override // T1.o
    public void setAllowingReadAccessToURL(q qVar, String str) {
    }

    @Override // T1.o
    public void setAllowsAirPlayForMediaPlayback(q qVar, boolean z3) {
    }

    @Override // T1.o
    public void setAllowsBackForwardNavigationGestures(q qVar, boolean z3) {
    }

    @Override // T1.o
    public void setAllowsInlineMediaPlayback(q qVar, boolean z3) {
    }

    @Override // T1.o
    public void setAllowsLinkPreview(q qVar, boolean z3) {
    }

    @Override // T1.o
    public void setAllowsPictureInPictureMediaPlayback(q qVar, boolean z3) {
    }

    @Override // T1.o
    public void setAutoManageStatusBarEnabled(q qVar, boolean z3) {
    }

    @Override // T1.o
    public void setAutomaticallyAdjustContentInsets(q qVar, boolean z3) {
    }

    @Override // T1.o
    public void setBounces(q qVar, boolean z3) {
    }

    @Override // T1.o
    public void setContentInset(q qVar, ReadableMap readableMap) {
    }

    @Override // T1.o
    public void setContentInsetAdjustmentBehavior(q qVar, String str) {
    }

    @Override // T1.o
    public void setContentMode(q qVar, String str) {
    }

    @Override // T1.o
    public void setDataDetectorTypes(q qVar, ReadableArray readableArray) {
    }

    @Override // T1.o
    public void setDecelerationRate(q qVar, double d3) {
    }

    @Override // T1.o
    public void setDirectionalLockEnabled(q qVar, boolean z3) {
    }

    @Override // T1.o
    public void setEnableApplePay(q qVar, boolean z3) {
    }

    @Override // T1.o
    public void setFraudulentWebsiteWarningEnabled(q qVar, boolean z3) {
    }

    @Override // T1.o
    public void setHasOnFileDownload(q qVar, boolean z3) {
    }

    @Override // T1.o
    public void setHideKeyboardAccessoryView(q qVar, boolean z3) {
    }

    @Override // T1.o
    public void setIndicatorStyle(q qVar, String str) {
    }

    @Override // T1.o
    public void setKeyboardDisplayRequiresUserAction(q qVar, boolean z3) {
    }

    @Override // T1.o
    public void setLimitsNavigationsToAppBoundDomains(q qVar, boolean z3) {
    }

    @Override // T1.o
    public void setMediaCapturePermissionGrantType(q qVar, String str) {
    }

    @Override // T1.o
    public void setPagingEnabled(q qVar, boolean z3) {
    }

    @Override // T1.o
    public void setPullToRefreshEnabled(q qVar, boolean z3) {
    }

    @Override // T1.o
    public void setRefreshControlLightMode(q qVar, boolean z3) {
    }

    @Override // T1.o
    public void setScrollEnabled(q qVar, boolean z3) {
    }

    @Override // T1.o
    public void setSharedCookiesEnabled(q qVar, boolean z3) {
    }

    @Override // T1.o
    @K1.a(name = "suppressMenuItems ")
    public void setSuppressMenuItems(q qVar, ReadableArray readableArray) {
    }

    @Override // T1.o
    public void setTextInteractionEnabled(q qVar, boolean z3) {
    }

    @Override // T1.o
    public void setUseSharedProcessPool(q qVar, boolean z3) {
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.facebook.react.uimanager.ViewManager
    public void addEventEmitters(B0 b02, q qVar) {
        qVar.getWebView().setWebViewClient(new h());
    }

    @Override // T1.o
    public void clearCache(q qVar, boolean z3) {
        qVar.getWebView().clearCache(z3);
    }

    @Override // T1.o
    public void clearFormData(q qVar) {
        qVar.getWebView().clearFormData();
    }

    @Override // T1.o
    public void clearHistory(q qVar) {
        qVar.getWebView().clearHistory();
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.facebook.react.uimanager.ViewManager
    public q createViewInstance(B0 b02) {
        return this.mRNCWebViewManagerImpl.d(b02);
    }

    @Override // T1.o
    public void goBack(q qVar) {
        qVar.getWebView().goBack();
    }

    @Override // T1.o
    public void goForward(q qVar) {
        qVar.getWebView().goForward();
    }

    @Override // T1.o
    public void injectJavaScript(q qVar, String str) {
        qVar.getWebView().h(str);
    }

    @Override // T1.o
    public void loadUrl(q qVar, String str) {
        qVar.getWebView().loadUrl(str);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.facebook.react.uimanager.BaseViewManager, com.facebook.react.uimanager.ViewManager
    public void onAfterUpdateTransaction(q qVar) {
        super.onAfterUpdateTransaction(qVar);
        this.mRNCWebViewManagerImpl.l(qVar);
    }

    @Override // com.facebook.react.uimanager.ViewManager
    public void onDropViewInstance(q qVar) {
        this.mRNCWebViewManagerImpl.m(qVar);
        super.onDropViewInstance(qVar);
    }

    @Override // T1.o
    public void postMessage(q qVar, String str) {
        try {
            JSONObject jSONObject = new JSONObject();
            jSONObject.put("data", str);
            qVar.getWebView().h("(function () {var event;var data = " + jSONObject.toString() + ";try {event = new MessageEvent('message', data);} catch (e) {event = document.createEvent('MessageEvent');event.initMessageEvent('message', true, true, data.data, data.origin, data.lastEventId, data.source);}document.dispatchEvent(event);})();");
        } catch (JSONException e3) {
            throw new RuntimeException(e3);
        }
    }

    @Override // com.facebook.react.uimanager.ViewManager
    public void receiveCommand(q qVar, String str, ReadableArray readableArray) {
        super.receiveCommand(qVar, str, readableArray);
    }

    @Override // T1.o
    public void reload(q qVar) {
        qVar.getWebView().reload();
    }

    @Override // T1.o
    public void requestFocus(q qVar) {
        qVar.requestFocus();
    }

    @Override // T1.o
    @K1.a(name = "allowFileAccess")
    public void setAllowFileAccess(q qVar, boolean z3) {
        this.mRNCWebViewManagerImpl.n(qVar, z3);
    }

    @Override // T1.o
    @K1.a(name = "allowFileAccessFromFileURLs")
    public void setAllowFileAccessFromFileURLs(q qVar, boolean z3) {
        this.mRNCWebViewManagerImpl.o(qVar, z3);
    }

    @Override // T1.o
    @K1.a(name = "allowUniversalAccessFromFileURLs")
    public void setAllowUniversalAccessFromFileURLs(q qVar, boolean z3) {
        this.mRNCWebViewManagerImpl.p(qVar, z3);
    }

    @Override // T1.o
    @K1.a(name = "allowsFullscreenVideo")
    public void setAllowsFullscreenVideo(q qVar, boolean z3) {
        this.mRNCWebViewManagerImpl.q(qVar, z3);
    }

    @Override // T1.o
    @K1.a(name = "allowsProtectedMedia")
    public void setAllowsProtectedMedia(q qVar, boolean z3) {
        this.mRNCWebViewManagerImpl.r(qVar, z3);
    }

    @Override // T1.o
    @K1.a(name = "androidLayerType")
    public void setAndroidLayerType(q qVar, String str) {
        this.mRNCWebViewManagerImpl.s(qVar, str);
    }

    @Override // T1.o
    @K1.a(name = "applicationNameForUserAgent")
    public void setApplicationNameForUserAgent(q qVar, String str) {
        this.mRNCWebViewManagerImpl.t(qVar, str);
    }

    @Override // T1.o
    @K1.a(name = "basicAuthCredential")
    public void setBasicAuthCredential(q qVar, ReadableMap readableMap) {
        this.mRNCWebViewManagerImpl.u(qVar, readableMap);
    }

    @Override // T1.o
    @K1.a(name = "cacheEnabled")
    public void setCacheEnabled(q qVar, boolean z3) {
        this.mRNCWebViewManagerImpl.v(qVar, z3);
    }

    @Override // T1.o
    @K1.a(name = "cacheMode")
    public void setCacheMode(q qVar, String str) {
        this.mRNCWebViewManagerImpl.w(qVar, str);
    }

    @Override // T1.o
    @K1.a(name = "domStorageEnabled")
    public void setDomStorageEnabled(q qVar, boolean z3) {
        this.mRNCWebViewManagerImpl.x(qVar, z3);
    }

    @Override // T1.o
    @K1.a(name = "downloadingMessage")
    public void setDownloadingMessage(q qVar, String str) {
        this.mRNCWebViewManagerImpl.y(str);
    }

    @Override // T1.o
    @K1.a(name = "forceDarkOn")
    public void setForceDarkOn(q qVar, boolean z3) {
        this.mRNCWebViewManagerImpl.z(qVar, z3);
    }

    @Override // T1.o
    @K1.a(name = "geolocationEnabled")
    public void setGeolocationEnabled(q qVar, boolean z3) {
        this.mRNCWebViewManagerImpl.A(qVar, z3);
    }

    @Override // T1.o
    @K1.a(name = "hasOnOpenWindowEvent")
    public void setHasOnOpenWindowEvent(q qVar, boolean z3) {
        this.mRNCWebViewManagerImpl.B(qVar, z3);
    }

    @Override // T1.o
    @K1.a(name = "hasOnScroll")
    public void setHasOnScroll(q qVar, boolean z3) {
        this.mRNCWebViewManagerImpl.C(qVar, z3);
    }

    @Override // T1.o
    @K1.a(name = "incognito")
    public void setIncognito(q qVar, boolean z3) {
        this.mRNCWebViewManagerImpl.D(qVar, z3);
    }

    @Override // T1.o
    @K1.a(name = "injectedJavaScript")
    public void setInjectedJavaScript(q qVar, String str) {
        this.mRNCWebViewManagerImpl.E(qVar, str);
    }

    @Override // T1.o
    @K1.a(name = "injectedJavaScriptBeforeContentLoaded")
    public void setInjectedJavaScriptBeforeContentLoaded(q qVar, String str) {
        this.mRNCWebViewManagerImpl.F(qVar, str);
    }

    @Override // T1.o
    @K1.a(name = "injectedJavaScriptBeforeContentLoadedForMainFrameOnly")
    public void setInjectedJavaScriptBeforeContentLoadedForMainFrameOnly(q qVar, boolean z3) {
        this.mRNCWebViewManagerImpl.G(qVar, z3);
    }

    @Override // T1.o
    @K1.a(name = "injectedJavaScriptForMainFrameOnly")
    public void setInjectedJavaScriptForMainFrameOnly(q qVar, boolean z3) {
        this.mRNCWebViewManagerImpl.H(qVar, z3);
    }

    @Override // T1.o
    @K1.a(name = "injectedJavaScriptObject")
    public void setInjectedJavaScriptObject(q qVar, String str) {
        this.mRNCWebViewManagerImpl.I(qVar, str);
    }

    @Override // T1.o
    @K1.a(name = "javaScriptCanOpenWindowsAutomatically")
    public void setJavaScriptCanOpenWindowsAutomatically(q qVar, boolean z3) {
        this.mRNCWebViewManagerImpl.J(qVar, z3);
    }

    @Override // T1.o
    @K1.a(name = "javaScriptEnabled")
    public void setJavaScriptEnabled(q qVar, boolean z3) {
        this.mRNCWebViewManagerImpl.K(qVar, z3);
    }

    @Override // T1.o
    @K1.a(name = "lackPermissionToDownloadMessage")
    public void setLackPermissionToDownloadMessage(q qVar, String str) {
        this.mRNCWebViewManagerImpl.L(str);
    }

    @Override // T1.o
    @K1.a(name = "mediaPlaybackRequiresUserAction")
    public void setMediaPlaybackRequiresUserAction(q qVar, boolean z3) {
        this.mRNCWebViewManagerImpl.M(qVar, z3);
    }

    @Override // T1.o
    @K1.a(name = "menuItems")
    public void setMenuItems(q qVar, ReadableArray readableArray) {
        this.mRNCWebViewManagerImpl.N(qVar, readableArray);
    }

    @Override // T1.o
    @K1.a(name = "messagingEnabled")
    public void setMessagingEnabled(q qVar, boolean z3) {
        this.mRNCWebViewManagerImpl.O(qVar, z3);
    }

    @Override // T1.o
    @K1.a(name = "messagingModuleName")
    public void setMessagingModuleName(q qVar, String str) {
        this.mRNCWebViewManagerImpl.P(qVar, str);
    }

    @Override // T1.o
    @K1.a(name = "minimumFontSize")
    public void setMinimumFontSize(q qVar, int i3) {
        this.mRNCWebViewManagerImpl.Q(qVar, i3);
    }

    @Override // T1.o
    @K1.a(name = "mixedContentMode")
    public void setMixedContentMode(q qVar, String str) {
        this.mRNCWebViewManagerImpl.R(qVar, str);
    }

    @Override // T1.o
    @K1.a(name = "nestedScrollEnabled")
    public void setNestedScrollEnabled(q qVar, boolean z3) {
        this.mRNCWebViewManagerImpl.S(qVar, z3);
    }

    @Override // T1.o
    @K1.a(name = "newSource")
    public void setNewSource(q qVar, ReadableMap readableMap) {
        this.mRNCWebViewManagerImpl.b0(qVar, readableMap);
    }

    @Override // T1.o
    @K1.a(name = "overScrollMode")
    public void setOverScrollMode(q qVar, String str) {
        this.mRNCWebViewManagerImpl.T(qVar, str);
    }

    @Override // T1.o
    @K1.a(name = "saveFormDataDisabled")
    public void setSaveFormDataDisabled(q qVar, boolean z3) {
        this.mRNCWebViewManagerImpl.U(qVar, z3);
    }

    @Override // T1.o
    @K1.a(name = "scalesPageToFit")
    public void setScalesPageToFit(q qVar, boolean z3) {
        this.mRNCWebViewManagerImpl.V(qVar, z3);
    }

    @Override // T1.o
    @K1.a(name = "setBuiltInZoomControls")
    public void setSetBuiltInZoomControls(q qVar, boolean z3) {
        this.mRNCWebViewManagerImpl.W(qVar, z3);
    }

    @Override // T1.o
    @K1.a(name = "setDisplayZoomControls")
    public void setSetDisplayZoomControls(q qVar, boolean z3) {
        this.mRNCWebViewManagerImpl.X(qVar, z3);
    }

    @Override // T1.o
    @K1.a(name = "setSupportMultipleWindows")
    public void setSetSupportMultipleWindows(q qVar, boolean z3) {
        this.mRNCWebViewManagerImpl.Y(qVar, z3);
    }

    @Override // T1.o
    @K1.a(name = "showsHorizontalScrollIndicator")
    public void setShowsHorizontalScrollIndicator(q qVar, boolean z3) {
        this.mRNCWebViewManagerImpl.Z(qVar, z3);
    }

    @Override // T1.o
    @K1.a(name = "showsVerticalScrollIndicator")
    public void setShowsVerticalScrollIndicator(q qVar, boolean z3) {
        this.mRNCWebViewManagerImpl.a0(qVar, z3);
    }

    @Override // T1.o
    @K1.a(name = "textZoom")
    public void setTextZoom(q qVar, int i3) {
        this.mRNCWebViewManagerImpl.c0(qVar, i3);
    }

    @Override // T1.o
    @K1.a(name = "thirdPartyCookiesEnabled")
    public void setThirdPartyCookiesEnabled(q qVar, boolean z3) {
        this.mRNCWebViewManagerImpl.d0(qVar, z3);
    }

    @Override // T1.o
    @K1.a(name = "userAgent")
    public void setUserAgent(q qVar, String str) {
        this.mRNCWebViewManagerImpl.e0(qVar, str);
    }

    @Override // T1.o
    @K1.a(name = "webviewDebuggingEnabled")
    public void setWebviewDebuggingEnabled(q qVar, boolean z3) {
        this.mRNCWebViewManagerImpl.g0(qVar, z3);
    }

    @Override // T1.o
    public void stopLoading(q qVar) {
        qVar.getWebView().stopLoading();
    }
}
