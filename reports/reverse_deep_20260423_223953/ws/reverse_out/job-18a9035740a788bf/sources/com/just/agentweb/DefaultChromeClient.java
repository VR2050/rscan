package com.just.agentweb;

import android.app.Activity;
import android.content.Context;
import android.graphics.Bitmap;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;
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
import com.just.agentweb.AgentActionFragment;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/* JADX INFO: loaded from: classes3.dex */
public class DefaultChromeClient extends MiddlewareWebChromeBase {
    public static final String ANDROID_WEBCHROMECLIENT_PATH = "android.webkit.WebChromeClient";
    public static final int FROM_CODE_INTENTION = 24;
    public static final int FROM_CODE_INTENTION_LOCATION = 96;
    private String TAG;
    private WeakReference<Activity> mActivityWeakReference;
    private WeakReference<AbsAgentWebUIController> mAgentWebUIController;
    private GeolocationPermissions.Callback mCallback;
    private Object mFileChooser;
    private IVideo mIVideo;
    private IndicatorController mIndicatorController;
    private boolean mIsWrapper;
    private String mOrigin;
    private PermissionInterceptor mPermissionInterceptor;
    private AgentActionFragment.PermissionListener mPermissionListener;
    private android.webkit.WebChromeClient mWebChromeClient;
    private WebView mWebView;

    DefaultChromeClient(Activity activity, IndicatorController indicatorController, android.webkit.WebChromeClient chromeClient, IVideo iVideo, PermissionInterceptor permissionInterceptor, WebView webView) {
        super(chromeClient);
        this.mActivityWeakReference = null;
        this.TAG = DefaultChromeClient.class.getSimpleName();
        this.mIsWrapper = false;
        this.mOrigin = null;
        this.mCallback = null;
        this.mAgentWebUIController = null;
        this.mPermissionListener = new AgentActionFragment.PermissionListener() { // from class: com.just.agentweb.DefaultChromeClient.1
            @Override // com.just.agentweb.AgentActionFragment.PermissionListener
            public void onRequestPermissionsResult(String[] permissions, int[] grantResults, Bundle extras) {
                if (extras.getInt(AgentActionFragment.KEY_FROM_INTENTION) == 96) {
                    boolean hasPermission = AgentWebUtils.hasPermission((Context) DefaultChromeClient.this.mActivityWeakReference.get(), permissions);
                    if (DefaultChromeClient.this.mCallback != null) {
                        if (hasPermission) {
                            DefaultChromeClient.this.mCallback.invoke(DefaultChromeClient.this.mOrigin, true, false);
                        } else {
                            DefaultChromeClient.this.mCallback.invoke(DefaultChromeClient.this.mOrigin, false, false);
                        }
                        DefaultChromeClient.this.mCallback = null;
                        DefaultChromeClient.this.mOrigin = null;
                    }
                    if (!hasPermission && DefaultChromeClient.this.mAgentWebUIController.get() != null) {
                        ((AbsAgentWebUIController) DefaultChromeClient.this.mAgentWebUIController.get()).onPermissionsDeny(AgentWebPermissions.LOCATION, AgentWebPermissions.ACTION_LOCATION, AgentWebPermissions.ACTION_LOCATION);
                    }
                }
            }
        };
        this.mIndicatorController = indicatorController;
        this.mIsWrapper = chromeClient != null;
        this.mWebChromeClient = chromeClient;
        this.mActivityWeakReference = new WeakReference<>(activity);
        this.mIVideo = iVideo;
        this.mPermissionInterceptor = permissionInterceptor;
        this.mWebView = webView;
        this.mAgentWebUIController = new WeakReference<>(AgentWebUtils.getAgentWebUIControllerByWebView(webView));
    }

    @Override // com.just.agentweb.WebChromeClientDelegate, android.webkit.WebChromeClient
    public void onProgressChanged(WebView view, int newProgress) {
        super.onProgressChanged(view, newProgress);
        IndicatorController indicatorController = this.mIndicatorController;
        if (indicatorController != null) {
            indicatorController.progress(view, newProgress);
        }
    }

    @Override // com.just.agentweb.WebChromeClientDelegate, android.webkit.WebChromeClient
    public void onReceivedTitle(WebView view, String title) {
        if (this.mIsWrapper) {
            super.onReceivedTitle(view, title);
        }
    }

    @Override // com.just.agentweb.WebChromeClientDelegate, android.webkit.WebChromeClient
    public boolean onJsAlert(WebView view, String url, String message, JsResult result) {
        if (this.mAgentWebUIController.get() != null) {
            this.mAgentWebUIController.get().onJsAlert(view, url, message);
        }
        result.confirm();
        return true;
    }

    @Override // com.just.agentweb.WebChromeClientDelegate, android.webkit.WebChromeClient
    public void onReceivedIcon(WebView view, Bitmap icon) {
        super.onReceivedIcon(view, icon);
    }

    @Override // com.just.agentweb.WebChromeClientDelegate, android.webkit.WebChromeClient
    public void onGeolocationPermissionsHidePrompt() {
        super.onGeolocationPermissionsHidePrompt();
    }

    @Override // com.just.agentweb.WebChromeClientDelegate, android.webkit.WebChromeClient
    public void onGeolocationPermissionsShowPrompt(String origin, GeolocationPermissions.Callback callback) {
        onGeolocationPermissionsShowPromptInternal(origin, callback);
    }

    private void onGeolocationPermissionsShowPromptInternal(String origin, GeolocationPermissions.Callback callback) {
        PermissionInterceptor permissionInterceptor = this.mPermissionInterceptor;
        if (permissionInterceptor != null && permissionInterceptor.intercept(this.mWebView.getUrl(), AgentWebPermissions.LOCATION, "location")) {
            callback.invoke(origin, false, false);
            return;
        }
        Activity mActivity = this.mActivityWeakReference.get();
        if (mActivity == null) {
            callback.invoke(origin, false, false);
            return;
        }
        List<String> deniedPermissions = AgentWebUtils.getDeniedPermissions(mActivity, AgentWebPermissions.LOCATION);
        if (deniedPermissions.isEmpty()) {
            LogUtils.i(this.TAG, "onGeolocationPermissionsShowPromptInternal:true");
            callback.invoke(origin, true, false);
            return;
        }
        Action mAction = Action.createPermissionsAction((String[]) deniedPermissions.toArray(new String[0]));
        mAction.setFromIntention(96);
        mAction.setPermissionListener(this.mPermissionListener);
        this.mCallback = callback;
        this.mOrigin = origin;
        AgentActionFragment.start(mActivity, mAction);
    }

    @Override // com.just.agentweb.WebChromeClientDelegate, android.webkit.WebChromeClient
    public boolean onJsPrompt(WebView view, String url, String message, String defaultValue, JsPromptResult result) {
        try {
            if (this.mAgentWebUIController.get() != null) {
                this.mAgentWebUIController.get().onJsPrompt(this.mWebView, url, message, defaultValue, result);
                return true;
            }
            return true;
        } catch (Exception e) {
            if (LogUtils.isDebug()) {
                e.printStackTrace();
                return true;
            }
            return true;
        }
    }

    @Override // com.just.agentweb.WebChromeClientDelegate, android.webkit.WebChromeClient
    public boolean onJsConfirm(WebView view, String url, String message, JsResult result) {
        if (this.mAgentWebUIController.get() != null) {
            this.mAgentWebUIController.get().onJsConfirm(view, url, message, result);
            return true;
        }
        return true;
    }

    @Override // com.just.agentweb.WebChromeClientDelegate, android.webkit.WebChromeClient
    public void onPermissionRequest(PermissionRequest request) {
        if (request == null) {
            return;
        }
        String[] resources = request.getResources();
        if (resources == null || resources.length <= 0) {
            request.deny();
            return;
        }
        Set<String> resourcesSet = new HashSet<>(Arrays.asList(resources));
        ArrayList<String> permissions = new ArrayList<>(resourcesSet.size());
        if (resourcesSet.contains("android.webkit.resource.VIDEO_CAPTURE")) {
            permissions.add("android.permission.CAMERA");
        }
        if (resourcesSet.contains("android.webkit.resource.AUDIO_CAPTURE")) {
            permissions.add("android.permission.RECORD_AUDIO");
        }
        PermissionInterceptor permissionInterceptor = this.mPermissionInterceptor;
        if (permissionInterceptor != null) {
            boolean intercept = permissionInterceptor.intercept(this.mWebView.getUrl(), (String[]) permissions.toArray(new String[0]), "onPermissionRequest");
            if (intercept) {
                return;
            }
        }
        if (this.mAgentWebUIController.get() != null) {
            this.mAgentWebUIController.get().onPermissionRequest(request);
        }
    }

    @Override // com.just.agentweb.WebChromeClientDelegate, android.webkit.WebChromeClient
    public void onPermissionRequestCanceled(PermissionRequest request) {
        super.onPermissionRequestCanceled(request);
    }

    @Override // com.just.agentweb.WebChromeClientDelegate, android.webkit.WebChromeClient
    public void onExceededDatabaseQuota(String url, String databaseIdentifier, long quota, long estimatedDatabaseSize, long totalQuota, WebStorage.QuotaUpdater quotaUpdater) {
        quotaUpdater.updateQuota(2 * totalQuota);
    }

    @Override // com.just.agentweb.WebChromeClientDelegate
    public void onReachedMaxAppCacheSize(long requiredStorage, long quota, WebStorage.QuotaUpdater quotaUpdater) {
        quotaUpdater.updateQuota(2 * requiredStorage);
    }

    @Override // com.just.agentweb.WebChromeClientDelegate, android.webkit.WebChromeClient
    public boolean onShowFileChooser(WebView webView, ValueCallback<Uri[]> filePathCallback, WebChromeClient.FileChooserParams fileChooserParams) {
        LogUtils.i(this.TAG, "openFileChooser>=5.0");
        return openFileChooserAboveL(webView, filePathCallback, fileChooserParams);
    }

    private boolean openFileChooserAboveL(WebView webView, ValueCallback<Uri[]> valueCallbacks, WebChromeClient.FileChooserParams fileChooserParams) {
        Activity mActivity;
        if (valueCallbacks == null || (mActivity = this.mActivityWeakReference.get()) == null || mActivity.isFinishing()) {
            return false;
        }
        return AgentWebUtils.showFileChooserCompat(mActivity, this.mWebView, valueCallbacks, fileChooserParams, this.mPermissionInterceptor, null, null, null);
    }

    @Override // com.just.agentweb.WebChromeClientDelegate
    public void openFileChooser(ValueCallback<Uri> uploadFile, String acceptType, String capture) {
        LogUtils.i(this.TAG, "openFileChooser>=4.1");
        createAndOpenCommonFileChooser(uploadFile, acceptType);
    }

    @Override // com.just.agentweb.WebChromeClientDelegate
    public void openFileChooser(ValueCallback<Uri> valueCallback) {
        Log.i(this.TAG, "openFileChooser<3.0");
        createAndOpenCommonFileChooser(valueCallback, "*/*");
    }

    @Override // com.just.agentweb.WebChromeClientDelegate
    public void openFileChooser(ValueCallback valueCallback, String acceptType) {
        Log.i(this.TAG, "openFileChooser>3.0");
        createAndOpenCommonFileChooser(valueCallback, acceptType);
    }

    private void createAndOpenCommonFileChooser(ValueCallback valueCallback, String mimeType) {
        if (valueCallback == null) {
            return;
        }
        Activity mActivity = this.mActivityWeakReference.get();
        if (mActivity == null || mActivity.isFinishing()) {
            valueCallback.onReceiveValue(new Object());
        } else {
            AgentWebUtils.showFileChooserCompat(mActivity, this.mWebView, null, null, this.mPermissionInterceptor, valueCallback, mimeType, null);
        }
    }

    @Override // com.just.agentweb.WebChromeClientDelegate, android.webkit.WebChromeClient
    public boolean onConsoleMessage(ConsoleMessage consoleMessage) {
        super.onConsoleMessage(consoleMessage);
        return true;
    }

    @Override // com.just.agentweb.WebChromeClientDelegate, android.webkit.WebChromeClient
    public void onShowCustomView(View view, WebChromeClient.CustomViewCallback callback) {
        IVideo iVideo = this.mIVideo;
        if (iVideo != null) {
            iVideo.onShowCustomView(view, callback);
        }
    }

    @Override // com.just.agentweb.WebChromeClientDelegate, android.webkit.WebChromeClient
    public void onHideCustomView() {
        IVideo iVideo = this.mIVideo;
        if (iVideo != null) {
            iVideo.onHideCustomView();
        }
    }
}
