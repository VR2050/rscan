package im.uwrkaxlmjj.ui.fragments;

import android.content.ClipData;
import android.content.DialogInterface;
import android.content.Intent;
import android.graphics.Bitmap;
import android.graphics.Rect;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.text.TextUtils;
import android.view.DisplayCutout;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewParent;
import android.view.WindowInsets;
import android.webkit.GeolocationPermissions;
import android.webkit.JsPromptResult;
import android.webkit.JsResult;
import android.webkit.PermissionRequest;
import android.webkit.ValueCallback;
import android.webkit.WebChromeClient;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.FrameLayout;
import android.widget.ImageView;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.tgnet.TLRPC2;
import im.uwrkaxlmjj.ui.actionbar.AlertDialog;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.components.toast.ToastUtils;
import im.uwrkaxlmjj.ui.fragments.DiscoveryFragment;
import im.uwrkaxlmjj.ui.hviews.dragView.DragCallBack;
import im.uwrkaxlmjj.ui.hviews.dragView.DragHelperFrameLayout;
import java.util.List;
import mpEIGo.juqQQs.esbSDO.R;
import org.webrtc.mozi.ProxyInfo;

/* JADX INFO: loaded from: classes5.dex */
public class TabWebFragment extends BaseFmts {
    private static final int REQUEST_CODE_FILE = 67;
    private static final int REQUEST_CODE_LOCATION = 99;
    private ChromeClient chromeClient;
    private DiscoveryFragment.Delegate delegate;
    private int extraDataReqToken;
    private ImageView imgReFresh;
    private WebView webView;
    private DragHelperFrameLayout webViewContainer;

    @Override // im.uwrkaxlmjj.ui.fragments.BaseFmts, androidx.fragment.app.Fragment
    public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
        DragHelperFrameLayout dragHelperFrameLayout = new DragHelperFrameLayout(getParentActivity());
        this.webViewContainer = dragHelperFrameLayout;
        dragHelperFrameLayout.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
        this.fragmentView = this.webViewContainer;
        this.webView = new WebView(getParentActivity());
        this.webViewContainer.setPadding(0, AndroidUtilities.statusBarHeight, 0, 0);
        this.webViewContainer.addView(this.webView, LayoutHelper.createFrame(-1, -1.0f));
        ImageView imageView = new ImageView(getParentActivity());
        this.imgReFresh = imageView;
        imageView.setImageResource(R.id.icon_refresh_web);
        FrameLayout.LayoutParams layoutParams = new FrameLayout.LayoutParams(AndroidUtilities.dp(68.0f), AndroidUtilities.dp(68.0f));
        layoutParams.gravity = 8388693;
        layoutParams.setMargins(0, 0, requireActivity().getResources().getDimensionPixelSize(R.dimen.dp_5), requireActivity().getResources().getDimensionPixelSize(R.dimen.dp_96));
        this.webViewContainer.addView(this.imgReFresh, layoutParams);
        DragHelperFrameLayout dragHelperFrameLayout2 = this.webViewContainer;
        dragHelperFrameLayout2.setViewDragCallBack(new DragCallBack(dragHelperFrameLayout2, this.imgReFresh) { // from class: im.uwrkaxlmjj.ui.fragments.TabWebFragment.1
            @Override // im.uwrkaxlmjj.ui.hviews.dragView.DragCallBack
            public List<Rect> getNotchRectList() {
                WindowInsets windowInsets;
                DisplayCutout displayCutout;
                if (Build.VERSION.SDK_INT >= 28 && (windowInsets = TabWebFragment.this.getParentActivity().getWindow().getDecorView().getRootWindowInsets()) != null && (displayCutout = windowInsets.getDisplayCutout()) != null) {
                    return displayCutout.getBoundingRects();
                }
                return super.getNotchRectList();
            }
        });
        return this.fragmentView;
    }

    @Override // androidx.fragment.app.Fragment
    public void onViewCreated(View view, Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);
        this.imgReFresh.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.fragments.TabWebFragment.2
            @Override // android.view.View.OnClickListener
            public void onClick(View v) {
                TabWebFragment.this.webView.reload();
            }
        });
        WebSettings webSettings = this.webView.getSettings();
        webSettings.setDisplayZoomControls(false);
        webSettings.setSupportZoom(false);
        webSettings.setBlockNetworkImage(false);
        if (Build.VERSION.SDK_INT >= 21) {
            webSettings.setMixedContentMode(0);
        }
        webSettings.setLoadsImagesAutomatically(true);
        webSettings.setCacheMode(-1);
        webSettings.setJavaScriptEnabled(true);
        webSettings.setDefaultTextEncodingName("utf-8");
        webSettings.setDomStorageEnabled(true);
        webSettings.setUseWideViewPort(true);
        webSettings.setLoadWithOverviewMode(true);
        webSettings.setTextZoom(100);
        webSettings.setAllowFileAccess(true);
        webSettings.setAllowFileAccessFromFileURLs(true);
        webSettings.setAllowUniversalAccessFromFileURLs(true);
        this.webView.setWebViewClient(new WebClient());
        WebView webView = this.webView;
        ChromeClient chromeClient = new ChromeClient();
        this.chromeClient = chromeClient;
        webView.setWebChromeClient(chromeClient);
    }

    @Override // im.uwrkaxlmjj.ui.fragments.BaseFmts
    protected void lazyLoadData() {
        TLRPC2.TL_DiscoveryPageSetting_SM s;
        super.lazyLoadData();
        DiscoveryFragment.Delegate delegate = this.delegate;
        if (delegate != null && delegate.getDiscoveryPageData() != null && this.delegate.getDiscoveryPageData().getS().size() > 0 && (s = this.delegate.getDiscoveryPageData().getS().get(0)) != null) {
            if (TextUtils.isEmpty(s.getUrl())) {
                getExtraDataLoginUrl(s);
                return;
            }
            if (!TextUtils.isEmpty(s.getUrl()) && (s.getUrl().startsWith("http:") || s.getUrl().startsWith("https:"))) {
                WebView webView = this.webView;
                if (webView != null) {
                    webView.loadUrl(s.getUrl());
                    return;
                }
                return;
            }
            ToastUtils.show(R.string.CancelLinkExpired);
        }
    }

    private void getExtraDataLoginUrl(TLRPC2.TL_DiscoveryPageSetting_SM s) {
        if (!getUserConfig().isClientActivated() || s == null || TextUtils.isEmpty(s.getTitle()) || this.extraDataReqToken != 0) {
            return;
        }
        AlertDialog progressDialog = new AlertDialog(getParentActivity(), 3);
        progressDialog.setOnCancelListener(new DialogInterface.OnCancelListener() { // from class: im.uwrkaxlmjj.ui.fragments.-$$Lambda$TabWebFragment$MUNdoz4lTB0JeGAveWPxxLpDvdE
            @Override // android.content.DialogInterface.OnCancelListener
            public final void onCancel(DialogInterface dialogInterface) {
                this.f$0.lambda$getExtraDataLoginUrl$0$TabWebFragment(dialogInterface);
            }
        });
        showDialog(progressDialog);
        TLRPC2.TL_GetLoginUrl req = new TLRPC2.TL_GetLoginUrl();
        req.app_code = s.getTitle();
        this.extraDataReqToken = getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.fragments.-$$Lambda$TabWebFragment$akf0nHMQX2JzT0643d52iEOXr2c
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$getExtraDataLoginUrl$2$TabWebFragment(tLObject, tL_error);
            }
        });
        getConnectionsManager().bindRequestToGuid(this.extraDataReqToken, this.classGuid);
    }

    public /* synthetic */ void lambda$getExtraDataLoginUrl$0$TabWebFragment(DialogInterface dialog) {
        if (this.extraDataReqToken != 0) {
            getConnectionsManager().cancelRequest(this.extraDataReqToken, false);
        }
    }

    public /* synthetic */ void lambda$getExtraDataLoginUrl$2$TabWebFragment(final TLObject response, final TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.fragments.-$$Lambda$TabWebFragment$FglaNw9WnHDySUSHflJTjjunmIE
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$1$TabWebFragment(error, response);
            }
        });
    }

    public /* synthetic */ void lambda$null$1$TabWebFragment(TLRPC.TL_error error, TLObject response) {
        String str;
        if (error == null && (response instanceof TLRPC2.TL_LoginUrlInfo)) {
            TLRPC2.TL_LoginUrlInfo res = (TLRPC2.TL_LoginUrlInfo) response;
            String url = res.url;
            if (!TextUtils.isEmpty(url) && (url.startsWith("http:") || url.startsWith("https:"))) {
                WebView webView = this.webView;
                if (webView != null) {
                    webView.loadUrl(url);
                }
            } else {
                ToastUtils.show(R.string.CancelLinkExpired);
            }
        } else {
            ToastUtils.show(R.string.FailedToGetLink);
            StringBuilder sb = new StringBuilder();
            sb.append("TabWebFmts getExtraDataLoginUrl error: ");
            if (error != null) {
                str = "errCode:" + error.code + ", errText:" + error.text;
            } else {
                str = "error is null";
            }
            sb.append(str);
            FileLog.e(sb.toString());
        }
        this.extraDataReqToken = 0;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void showDialog(String message, boolean canCancel, boolean canCancelTouchOutside, String negativeBtnText, DialogInterface.OnClickListener negativeBtnClickListener, String positiveBtnText, DialogInterface.OnClickListener positiveBtnClickListener, DialogInterface.OnCancelListener cancelListener, DialogInterface.OnDismissListener dismissListener) {
        if (message == null) {
            return;
        }
        AlertDialog.Builder builder = new AlertDialog.Builder(getParentActivity());
        builder.setMessage(message);
        if (negativeBtnText != null) {
            builder.setNegativeButton(negativeBtnText, negativeBtnClickListener);
        }
        if (positiveBtnText != null) {
            builder.setPositiveButton(positiveBtnText, positiveBtnClickListener);
        }
        builder.setOnCancelListener(cancelListener);
        builder.setOnDismissListener(dismissListener);
        AlertDialog dialog = builder.create();
        dialog.setCancelable(canCancel);
        dialog.setCanceledOnTouchOutside(canCancelTouchOutside);
        showDialog(dialog);
    }

    @Override // androidx.fragment.app.Fragment
    public void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode != 67) {
            return;
        }
        if (this.chromeClient.fileChooserCallback40 != null) {
            Uri result = null;
            if (resultCode == -1) {
                result = data == null ? null : data.getData();
            }
            this.chromeClient.fileChooserCallback40.onReceiveValue(result);
            this.chromeClient.fileChooserCallback40 = null;
            return;
        }
        if (this.chromeClient.fileChooserCallback != null) {
            Uri[] results = null;
            if (resultCode == -1 && data != null) {
                String dataString = data.getDataString();
                ClipData clipData = data.getClipData();
                if (clipData != null) {
                    results = new Uri[clipData.getItemCount()];
                    for (int i = 0; i < clipData.getItemCount(); i++) {
                        ClipData.Item item = clipData.getItemAt(i);
                        results[i] = item.getUri();
                    }
                }
                if (dataString != null) {
                    results = new Uri[]{Uri.parse(dataString)};
                }
            }
            this.chromeClient.fileChooserCallback.onReceiveValue(results);
            this.chromeClient.fileChooserCallback = null;
        }
    }

    @Override // androidx.fragment.app.Fragment
    public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] grantResults) {
        ChromeClient chromeClient;
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode != 99 || (chromeClient = this.chromeClient) == null) {
            return;
        }
        chromeClient.showRequestLocationPermissionDialog(permissions[0], chromeClient.mGeolocationPermissionsCallBack);
    }

    private void showProgressDialog() {
        AlertDialog progressDialog = new AlertDialog(getParentActivity(), 3);
        showDialog(progressDialog);
    }

    public void setDelegate(DiscoveryFragment.Delegate delegate) {
        this.delegate = delegate;
    }

    @Override // im.uwrkaxlmjj.ui.fragments.BaseFmts
    public boolean onBackPressed() {
        WebView webView = this.webView;
        if (webView != null && webView.canGoBack()) {
            this.webView.goBack();
            return true;
        }
        return super.onBackPressed();
    }

    @Override // im.uwrkaxlmjj.ui.fragments.BaseFmts, androidx.fragment.app.Fragment
    public void onDestroyView() {
        WebView webView = this.webView;
        if (webView != null) {
            webView.setLayerType(0, null);
            try {
                ViewParent parent = this.webView.getParent();
                if (parent != null) {
                    ((FrameLayout) parent).removeView(this.webView);
                }
                this.webView.stopLoading();
                this.webView.loadUrl("about:blank");
                this.webView.setWebViewClient(null);
                this.webView.setWebChromeClient(null);
                this.webView.destroy();
                this.webView = null;
            } catch (Exception e) {
                FileLog.e(e);
            }
        }
        super.onDestroyView();
        ChromeClient chromeClient = this.chromeClient;
        if (chromeClient != null) {
            chromeClient.fileChooserCallback = null;
            this.chromeClient.fileChooserCallback40 = null;
            this.chromeClient.mGeolocationPermissionsCallBack = null;
            this.chromeClient = null;
        }
        this.chromeClient = null;
        this.delegate = null;
        if (getParentActivity() != null) {
            getParentActivity().setRequestedOrientation(1);
        }
    }

    private class WebClient extends WebViewClient {
        private WebClient() {
        }

        @Override // android.webkit.WebViewClient
        public boolean shouldOverrideUrlLoading(WebView view, String url) {
            if (!TabWebFragment.this.isAdded()) {
                return false;
            }
            if (url != null) {
                try {
                    if (!url.contains(ProxyInfo.TYPE_HTTPS) && !url.contains("http") && TabWebFragment.this.getParentActivity() != null) {
                        Intent intent = new Intent("android.intent.action.VIEW", Uri.parse(url));
                        intent.putExtra("create_new_tab", true);
                        intent.putExtra("com.android.browser.application_id", TabWebFragment.this.getParentActivity().getPackageName());
                        TabWebFragment.this.getParentActivity().startActivity(intent);
                        return true;
                    }
                } catch (Throwable e) {
                    FileLog.e(TabWebFragment.class.getName(), e);
                    ToastUtils.show(R.string.NoAppCanHandleThis);
                    return true;
                }
            }
            view.loadUrl(url);
            return true;
        }

        @Override // android.webkit.WebViewClient
        public void onPageStarted(WebView view, String url, Bitmap favicon) {
            super.onPageStarted(view, url, favicon);
        }

        @Override // android.webkit.WebViewClient
        public void onPageFinished(WebView view, String url) {
            super.onPageFinished(view, url);
            TabWebFragment.this.dismissCurrentDialog();
        }

        @Override // android.webkit.WebViewClient
        public void onReceivedError(WebView view, int errorCode, String description, String failingUrl) {
            FileLog.e(TabWebFragment.class.getName() + " onReceivedError: code:" + errorCode + ", des:" + description + ", u:" + failingUrl);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    class ChromeClient extends WebChromeClient {
        private ValueCallback<Uri[]> fileChooserCallback;
        private ValueCallback<Uri> fileChooserCallback40;
        private GeolocationPermissions.Callback mGeolocationPermissionsCallBack;
        private boolean mIsRequestingLocationPermission;

        private ChromeClient() {
        }

        @Override // android.webkit.WebChromeClient
        public boolean onJsAlert(WebView view, String url, String message, JsResult result) {
            if (!TabWebFragment.this.isAdded()) {
                return false;
            }
            AlertDialog.Builder builder = new AlertDialog.Builder(TabWebFragment.this.getParentActivity());
            builder.setMessage(message);
            TabWebFragment.this.showDialog(builder.create());
            return true;
        }

        @Override // android.webkit.WebChromeClient
        public boolean onJsConfirm(WebView view, String url, String message, final JsResult result) {
            if (!TabWebFragment.this.isAdded()) {
                return false;
            }
            AlertDialog.Builder builder = new AlertDialog.Builder(TabWebFragment.this.getParentActivity());
            builder.setMessage(message);
            builder.setPositiveButton(LocaleController.getString(R.string.OK), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.fragments.-$$Lambda$TabWebFragment$ChromeClient$T3MrwwQsrEjkPAEWiQGPyidfZxE
                @Override // android.content.DialogInterface.OnClickListener
                public final void onClick(DialogInterface dialogInterface, int i) {
                    result.confirm();
                }
            });
            builder.setNegativeButton(LocaleController.getString(R.string.Cancel), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.fragments.-$$Lambda$TabWebFragment$ChromeClient$_0DV8YbKJsbrhVpThkn2OtGqmSw
                @Override // android.content.DialogInterface.OnClickListener
                public final void onClick(DialogInterface dialogInterface, int i) {
                    result.cancel();
                }
            });
            TabWebFragment.this.showDialog(builder.create());
            return true;
        }

        @Override // android.webkit.WebChromeClient
        public boolean onJsPrompt(WebView view, String url, String message, String defaultValue, JsPromptResult result) {
            return super.onJsPrompt(view, url, message, defaultValue, result);
        }

        @Override // android.webkit.WebChromeClient
        public boolean onJsBeforeUnload(WebView view, String url, String message, JsResult result) {
            return super.onJsBeforeUnload(view, url, message, result);
        }

        @Override // android.webkit.WebChromeClient
        public void onGeolocationPermissionsShowPrompt(String origin, GeolocationPermissions.Callback callback) {
            if (!TabWebFragment.this.isAdded() || this.mIsRequestingLocationPermission) {
                return;
            }
            this.mIsRequestingLocationPermission = true;
            this.mGeolocationPermissionsCallBack = callback;
            if (ContextCompat.checkSelfPermission(TabWebFragment.this.getParentActivity(), origin) != 0) {
                String[] per = {origin};
                ActivityCompat.requestPermissions(TabWebFragment.this.getParentActivity(), per, 99);
            } else {
                showRequestLocationPermissionDialog(origin, callback);
            }
        }

        @Override // android.webkit.WebChromeClient
        public void onPermissionRequest(PermissionRequest request) {
            if (TabWebFragment.this.isAdded() && Build.VERSION.SDK_INT >= 21) {
                try {
                    request.grant(request.getResources());
                } catch (Exception e) {
                }
            }
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void showRequestLocationPermissionDialog(final String origin, final GeolocationPermissions.Callback callback) {
            if (TabWebFragment.this.isAdded() && callback != null) {
                TabWebFragment.this.showDialog(LocaleController.getString(R.string.RequestPermissionOfLocationDoYouAgreement), false, false, LocaleController.getString(R.string.Decline), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.fragments.-$$Lambda$TabWebFragment$ChromeClient$CnGLuCcPhNIu_K8KgdiTPxDSD64
                    @Override // android.content.DialogInterface.OnClickListener
                    public final void onClick(DialogInterface dialogInterface, int i) {
                        this.f$0.lambda$showRequestLocationPermissionDialog$2$TabWebFragment$ChromeClient(callback, origin, dialogInterface, i);
                    }
                }, LocaleController.getString(R.string.Agree), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.fragments.-$$Lambda$TabWebFragment$ChromeClient$vxBN3S8p1K8e9IMsQOaMxHRE3fA
                    @Override // android.content.DialogInterface.OnClickListener
                    public final void onClick(DialogInterface dialogInterface, int i) {
                        this.f$0.lambda$showRequestLocationPermissionDialog$3$TabWebFragment$ChromeClient(callback, origin, dialogInterface, i);
                    }
                }, new DialogInterface.OnCancelListener() { // from class: im.uwrkaxlmjj.ui.fragments.-$$Lambda$TabWebFragment$ChromeClient$sdI7D9f4bPGoJm6hmqmKtPqVnHc
                    @Override // android.content.DialogInterface.OnCancelListener
                    public final void onCancel(DialogInterface dialogInterface) {
                        this.f$0.lambda$showRequestLocationPermissionDialog$4$TabWebFragment$ChromeClient(callback, origin, dialogInterface);
                    }
                }, new DialogInterface.OnDismissListener() { // from class: im.uwrkaxlmjj.ui.fragments.-$$Lambda$TabWebFragment$ChromeClient$OYH6c06hlfgdApitf15SqqMr4BE
                    @Override // android.content.DialogInterface.OnDismissListener
                    public final void onDismiss(DialogInterface dialogInterface) {
                        this.f$0.lambda$showRequestLocationPermissionDialog$5$TabWebFragment$ChromeClient(dialogInterface);
                    }
                });
            }
        }

        public /* synthetic */ void lambda$showRequestLocationPermissionDialog$2$TabWebFragment$ChromeClient(GeolocationPermissions.Callback callback, String origin, DialogInterface dialog, int which) {
            if (callback != null) {
                callback.invoke(origin, false, false);
            }
            this.mIsRequestingLocationPermission = false;
        }

        public /* synthetic */ void lambda$showRequestLocationPermissionDialog$3$TabWebFragment$ChromeClient(GeolocationPermissions.Callback callback, String origin, DialogInterface dialog, int which) {
            if (callback != null) {
                callback.invoke(origin, true, false);
            }
            this.mIsRequestingLocationPermission = false;
        }

        public /* synthetic */ void lambda$showRequestLocationPermissionDialog$4$TabWebFragment$ChromeClient(GeolocationPermissions.Callback callback, String origin, DialogInterface dialog) {
            if (callback != null) {
                callback.invoke(origin, false, false);
            }
            this.mIsRequestingLocationPermission = false;
        }

        public /* synthetic */ void lambda$showRequestLocationPermissionDialog$5$TabWebFragment$ChromeClient(DialogInterface dialog) {
            this.mIsRequestingLocationPermission = false;
        }

        public void openFileChooser(ValueCallback<Uri> valueCallback) {
            this.fileChooserCallback40 = valueCallback;
            TabWebFragment.this.openFileChoosers();
        }

        public void openFileChooser(ValueCallback<Uri> valueCallback, String acceptType) {
            this.fileChooserCallback40 = valueCallback;
            TabWebFragment.this.openFileChoosers();
        }

        public void openFileChooser(ValueCallback<Uri> valueCallback, String acceptType, String capture) {
            this.fileChooserCallback40 = valueCallback;
            TabWebFragment.this.openFileChoosers();
        }

        @Override // android.webkit.WebChromeClient
        public boolean onShowFileChooser(WebView webView, ValueCallback<Uri[]> filePathCallback, WebChromeClient.FileChooserParams fileChooserParams) {
            this.fileChooserCallback = filePathCallback;
            TabWebFragment.this.openFileChoosers();
            return true;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void openFileChoosers() {
        try {
            Intent i = new Intent("android.intent.action.GET_CONTENT");
            i.addCategory("android.intent.category.OPENABLE");
            i.setType("image/*");
            startActivityForResult(Intent.createChooser(i, "Image Chooser"), 67);
        } catch (Throwable e) {
            ToastUtils.show((CharSequence) "Open Failed.");
            FileLog.e(getClass().getName() + " openFileChoosers error: " + e.getMessage());
        }
    }
}
