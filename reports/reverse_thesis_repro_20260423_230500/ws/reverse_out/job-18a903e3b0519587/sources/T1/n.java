package T1;

import android.view.View;
import com.facebook.react.bridge.ReadableArray;
import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.uimanager.AbstractC0445g;
import com.facebook.react.uimanager.BaseViewManager;

/* JADX INFO: loaded from: classes.dex */
public class n extends AbstractC0445g {
    public n(BaseViewManager baseViewManager) {
        super(baseViewManager);
    }

    @Override // com.facebook.react.uimanager.AbstractC0445g, com.facebook.react.uimanager.Q0
    public void a(View view, String str, ReadableArray readableArray) {
        str.hashCode();
        switch (str) {
            case "goBack":
                ((o) this.f7604a).goBack(view);
                break;
            case "stopLoading":
                ((o) this.f7604a).stopLoading(view);
                break;
            case "reload":
                ((o) this.f7604a).reload(view);
                break;
            case "clearCache":
                ((o) this.f7604a).clearCache(view, readableArray.getBoolean(0));
                break;
            case "goForward":
                ((o) this.f7604a).goForward(view);
                break;
            case "clearFormData":
                ((o) this.f7604a).clearFormData(view);
                break;
            case "loadUrl":
                ((o) this.f7604a).loadUrl(view, readableArray.getString(0));
                break;
            case "clearHistory":
                ((o) this.f7604a).clearHistory(view);
                break;
            case "requestFocus":
                ((o) this.f7604a).requestFocus(view);
                break;
            case "postMessage":
                ((o) this.f7604a).postMessage(view, readableArray.getString(0));
                break;
            case "injectJavaScript":
                ((o) this.f7604a).injectJavaScript(view, readableArray.getString(0));
                break;
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // com.facebook.react.uimanager.AbstractC0445g, com.facebook.react.uimanager.Q0
    public void b(View view, String str, Object obj) {
        str.hashCode();
        switch (str) {
            case "allowFileAccessFromFileURLs":
                ((o) this.f7604a).setAllowFileAccessFromFileURLs(view, obj != null ? ((Boolean) obj).booleanValue() : false);
                break;
            case "sharedCookiesEnabled":
                ((o) this.f7604a).setSharedCookiesEnabled(view, obj != null ? ((Boolean) obj).booleanValue() : false);
                break;
            case "allowsPictureInPictureMediaPlayback":
                ((o) this.f7604a).setAllowsPictureInPictureMediaPlayback(view, obj != null ? ((Boolean) obj).booleanValue() : false);
                break;
            case "allowsProtectedMedia":
                ((o) this.f7604a).setAllowsProtectedMedia(view, obj != null ? ((Boolean) obj).booleanValue() : false);
                break;
            case "saveFormDataDisabled":
                ((o) this.f7604a).setSaveFormDataDisabled(view, obj != null ? ((Boolean) obj).booleanValue() : false);
                break;
            case "textInteractionEnabled":
                ((o) this.f7604a).setTextInteractionEnabled(view, obj != null ? ((Boolean) obj).booleanValue() : true);
                break;
            case "injectedJavaScriptBeforeContentLoaded":
                ((o) this.f7604a).setInjectedJavaScriptBeforeContentLoaded(view, obj != null ? (String) obj : null);
                break;
            case "directionalLockEnabled":
                ((o) this.f7604a).setDirectionalLockEnabled(view, obj != null ? ((Boolean) obj).booleanValue() : true);
                break;
            case "javaScriptEnabled":
                ((o) this.f7604a).setJavaScriptEnabled(view, obj != null ? ((Boolean) obj).booleanValue() : true);
                break;
            case "messagingEnabled":
                ((o) this.f7604a).setMessagingEnabled(view, obj != null ? ((Boolean) obj).booleanValue() : false);
                break;
            case "indicatorStyle":
                ((o) this.f7604a).setIndicatorStyle(view, (String) obj);
                break;
            case "dataDetectorTypes":
                ((o) this.f7604a).setDataDetectorTypes(view, (ReadableArray) obj);
                break;
            case "menuItems":
                ((o) this.f7604a).setMenuItems(view, (ReadableArray) obj);
                break;
            case "incognito":
                ((o) this.f7604a).setIncognito(view, obj != null ? ((Boolean) obj).booleanValue() : false);
                break;
            case "allowingReadAccessToURL":
                ((o) this.f7604a).setAllowingReadAccessToURL(view, obj != null ? (String) obj : null);
                break;
            case "overScrollMode":
                ((o) this.f7604a).setOverScrollMode(view, obj != null ? (String) obj : null);
                break;
            case "scrollEnabled":
                ((o) this.f7604a).setScrollEnabled(view, obj != null ? ((Boolean) obj).booleanValue() : true);
                break;
            case "keyboardDisplayRequiresUserAction":
                ((o) this.f7604a).setKeyboardDisplayRequiresUserAction(view, obj != null ? ((Boolean) obj).booleanValue() : true);
                break;
            case "domStorageEnabled":
                ((o) this.f7604a).setDomStorageEnabled(view, obj != null ? ((Boolean) obj).booleanValue() : false);
                break;
            case "allowsLinkPreview":
                ((o) this.f7604a).setAllowsLinkPreview(view, obj != null ? ((Boolean) obj).booleanValue() : true);
                break;
            case "useSharedProcessPool":
                ((o) this.f7604a).setUseSharedProcessPool(view, obj != null ? ((Boolean) obj).booleanValue() : true);
                break;
            case "textZoom":
                ((o) this.f7604a).setTextZoom(view, obj != null ? ((Double) obj).intValue() : 0);
                break;
            case "showsVerticalScrollIndicator":
                ((o) this.f7604a).setShowsVerticalScrollIndicator(view, obj != null ? ((Boolean) obj).booleanValue() : true);
                break;
            case "forceDarkOn":
                ((o) this.f7604a).setForceDarkOn(view, obj != null ? ((Boolean) obj).booleanValue() : false);
                break;
            case "minimumFontSize":
                ((o) this.f7604a).setMinimumFontSize(view, obj != null ? ((Double) obj).intValue() : 0);
                break;
            case "hideKeyboardAccessoryView":
                ((o) this.f7604a).setHideKeyboardAccessoryView(view, obj != null ? ((Boolean) obj).booleanValue() : false);
                break;
            case "allowUniversalAccessFromFileURLs":
                ((o) this.f7604a).setAllowUniversalAccessFromFileURLs(view, obj != null ? ((Boolean) obj).booleanValue() : false);
                break;
            case "mediaCapturePermissionGrantType":
                ((o) this.f7604a).setMediaCapturePermissionGrantType(view, (String) obj);
                break;
            case "newSource":
                ((o) this.f7604a).setNewSource(view, (ReadableMap) obj);
                break;
            case "hasOnFileDownload":
                ((o) this.f7604a).setHasOnFileDownload(view, obj != null ? ((Boolean) obj).booleanValue() : false);
                break;
            case "cacheMode":
                ((o) this.f7604a).setCacheMode(view, (String) obj);
                break;
            case "pagingEnabled":
                ((o) this.f7604a).setPagingEnabled(view, obj != null ? ((Boolean) obj).booleanValue() : false);
                break;
            case "contentMode":
                ((o) this.f7604a).setContentMode(view, (String) obj);
                break;
            case "messagingModuleName":
                ((o) this.f7604a).setMessagingModuleName(view, obj != null ? (String) obj : null);
                break;
            case "hasOnOpenWindowEvent":
                ((o) this.f7604a).setHasOnOpenWindowEvent(view, obj != null ? ((Boolean) obj).booleanValue() : false);
                break;
            case "javaScriptCanOpenWindowsAutomatically":
                ((o) this.f7604a).setJavaScriptCanOpenWindowsAutomatically(view, obj != null ? ((Boolean) obj).booleanValue() : false);
                break;
            case "setDisplayZoomControls":
                ((o) this.f7604a).setSetDisplayZoomControls(view, obj != null ? ((Boolean) obj).booleanValue() : false);
                break;
            case "allowsFullscreenVideo":
                ((o) this.f7604a).setAllowsFullscreenVideo(view, obj != null ? ((Boolean) obj).booleanValue() : false);
                break;
            case "nestedScrollEnabled":
                ((o) this.f7604a).setNestedScrollEnabled(view, obj != null ? ((Boolean) obj).booleanValue() : false);
                break;
            case "injectedJavaScriptBeforeContentLoadedForMainFrameOnly":
                ((o) this.f7604a).setInjectedJavaScriptBeforeContentLoadedForMainFrameOnly(view, obj != null ? ((Boolean) obj).booleanValue() : true);
                break;
            case "hasOnScroll":
                ((o) this.f7604a).setHasOnScroll(view, obj != null ? ((Boolean) obj).booleanValue() : false);
                break;
            case "bounces":
                ((o) this.f7604a).setBounces(view, obj != null ? ((Boolean) obj).booleanValue() : true);
                break;
            case "setSupportMultipleWindows":
                ((o) this.f7604a).setSetSupportMultipleWindows(view, obj != null ? ((Boolean) obj).booleanValue() : true);
                break;
            case "lackPermissionToDownloadMessage":
                ((o) this.f7604a).setLackPermissionToDownloadMessage(view, obj != null ? (String) obj : null);
                break;
            case "injectedJavaScript":
                ((o) this.f7604a).setInjectedJavaScript(view, obj != null ? (String) obj : null);
                break;
            case "automaticallyAdjustContentInsets":
                ((o) this.f7604a).setAutomaticallyAdjustContentInsets(view, obj != null ? ((Boolean) obj).booleanValue() : true);
                break;
            case "userAgent":
                ((o) this.f7604a).setUserAgent(view, obj != null ? (String) obj : null);
                break;
            case "allowsInlineMediaPlayback":
                ((o) this.f7604a).setAllowsInlineMediaPlayback(view, obj != null ? ((Boolean) obj).booleanValue() : false);
                break;
            case "cacheEnabled":
                ((o) this.f7604a).setCacheEnabled(view, obj != null ? ((Boolean) obj).booleanValue() : true);
                break;
            case "injectedJavaScriptForMainFrameOnly":
                ((o) this.f7604a).setInjectedJavaScriptForMainFrameOnly(view, obj != null ? ((Boolean) obj).booleanValue() : true);
                break;
            case "webviewDebuggingEnabled":
                ((o) this.f7604a).setWebviewDebuggingEnabled(view, obj != null ? ((Boolean) obj).booleanValue() : false);
                break;
            case "injectedJavaScriptObject":
                ((o) this.f7604a).setInjectedJavaScriptObject(view, obj != null ? (String) obj : null);
                break;
            case "applicationNameForUserAgent":
                ((o) this.f7604a).setApplicationNameForUserAgent(view, obj != null ? (String) obj : null);
                break;
            case "mixedContentMode":
                ((o) this.f7604a).setMixedContentMode(view, (String) obj);
                break;
            case "contentInset":
                ((o) this.f7604a).setContentInset(view, (ReadableMap) obj);
                break;
            case "allowsBackForwardNavigationGestures":
                ((o) this.f7604a).setAllowsBackForwardNavigationGestures(view, obj != null ? ((Boolean) obj).booleanValue() : false);
                break;
            case "allowsAirPlayForMediaPlayback":
                ((o) this.f7604a).setAllowsAirPlayForMediaPlayback(view, obj != null ? ((Boolean) obj).booleanValue() : false);
                break;
            case "allowFileAccess":
                ((o) this.f7604a).setAllowFileAccess(view, obj != null ? ((Boolean) obj).booleanValue() : false);
                break;
            case "limitsNavigationsToAppBoundDomains":
                ((o) this.f7604a).setLimitsNavigationsToAppBoundDomains(view, obj != null ? ((Boolean) obj).booleanValue() : false);
                break;
            case "setBuiltInZoomControls":
                ((o) this.f7604a).setSetBuiltInZoomControls(view, obj != null ? ((Boolean) obj).booleanValue() : true);
                break;
            case "pullToRefreshEnabled":
                ((o) this.f7604a).setPullToRefreshEnabled(view, obj != null ? ((Boolean) obj).booleanValue() : false);
                break;
            case "refreshControlLightMode":
                ((o) this.f7604a).setRefreshControlLightMode(view, obj != null ? ((Boolean) obj).booleanValue() : false);
                break;
            case "fraudulentWebsiteWarningEnabled":
                ((o) this.f7604a).setFraudulentWebsiteWarningEnabled(view, obj != null ? ((Boolean) obj).booleanValue() : true);
                break;
            case "geolocationEnabled":
                ((o) this.f7604a).setGeolocationEnabled(view, obj != null ? ((Boolean) obj).booleanValue() : false);
                break;
            case "downloadingMessage":
                ((o) this.f7604a).setDownloadingMessage(view, obj != null ? (String) obj : null);
                break;
            case "basicAuthCredential":
                ((o) this.f7604a).setBasicAuthCredential(view, (ReadableMap) obj);
                break;
            case "enableApplePay":
                ((o) this.f7604a).setEnableApplePay(view, obj != null ? ((Boolean) obj).booleanValue() : false);
                break;
            case "mediaPlaybackRequiresUserAction":
                ((o) this.f7604a).setMediaPlaybackRequiresUserAction(view, obj != null ? ((Boolean) obj).booleanValue() : true);
                break;
            case "thirdPartyCookiesEnabled":
                ((o) this.f7604a).setThirdPartyCookiesEnabled(view, obj != null ? ((Boolean) obj).booleanValue() : true);
                break;
            case "autoManageStatusBarEnabled":
                ((o) this.f7604a).setAutoManageStatusBarEnabled(view, obj != null ? ((Boolean) obj).booleanValue() : true);
                break;
            case "androidLayerType":
                ((o) this.f7604a).setAndroidLayerType(view, (String) obj);
                break;
            case "suppressMenuItems":
                ((o) this.f7604a).setSuppressMenuItems(view, (ReadableArray) obj);
                break;
            case "showsHorizontalScrollIndicator":
                ((o) this.f7604a).setShowsHorizontalScrollIndicator(view, obj != null ? ((Boolean) obj).booleanValue() : true);
                break;
            case "scalesPageToFit":
                ((o) this.f7604a).setScalesPageToFit(view, obj != null ? ((Boolean) obj).booleanValue() : true);
                break;
            case "decelerationRate":
                ((o) this.f7604a).setDecelerationRate(view, obj == null ? 0.0d : ((Double) obj).doubleValue());
                break;
            case "contentInsetAdjustmentBehavior":
                ((o) this.f7604a).setContentInsetAdjustmentBehavior(view, (String) obj);
                break;
            default:
                super.b(view, str, obj);
                break;
        }
    }
}
