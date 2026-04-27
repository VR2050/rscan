package im.uwrkaxlmjj.ui.hui.discoveryweb;

import android.animation.AnimatorSet;
import android.app.Dialog;
import android.content.ClipData;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.SharedPreferences;
import android.graphics.Bitmap;
import android.graphics.Rect;
import android.net.Uri;
import android.net.http.SslError;
import android.os.Build;
import android.os.Bundle;
import android.os.Message;
import android.text.TextUtils;
import android.util.Log;
import android.view.DisplayCutout;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowInsets;
import android.view.animation.RotateAnimation;
import android.webkit.ConsoleMessage;
import android.webkit.GeolocationPermissions;
import android.webkit.JsPromptResult;
import android.webkit.JsResult;
import android.webkit.PermissionRequest;
import android.webkit.RenderProcessGoneDetail;
import android.webkit.SslErrorHandler;
import android.webkit.ValueCallback;
import android.webkit.WebChromeClient;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.FrameLayout;
import android.widget.ImageView;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;
import com.google.android.gms.common.internal.ImagesContract;
import com.just.agentweb.AgentWeb;
import com.just.agentweb.DefaultWebClient;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.ui.actionbar.AlertDialog;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.RadialProgressView;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import im.uwrkaxlmjj.ui.components.toast.ToastUtils;
import im.uwrkaxlmjj.ui.hviews.dragView.DragCallBack;
import im.uwrkaxlmjj.ui.hviews.dragView.DragHelperFrameLayout;
import java.util.List;
import mpEIGo.juqQQs.esbSDO.R;
import org.webrtc.mozi.ProxyInfo;

/* JADX INFO: loaded from: classes5.dex */
public class DiscoveryJumpToPage extends BaseFragment implements View.OnClickListener {
    private static volatile DiscoveryJumpToPage Instance = null;
    private static final int REQUEST_CODE_FILE = 67;
    private static final int REQUEST_CODE_LOCATION = 99;
    private AgentWeb agentWebView;
    private ChromeClient chromeClient;
    private View containerGuideRoot;
    private View containerMenu;
    private DragHelperFrameLayout dhfMenu;
    private DragHelperFrameLayout dragHelperFrameLayout;
    private ImageView imgRefresh;
    private ImageView ivClose;
    private ImageView ivShowMenuDialog;
    private AnimatorSet mAnimatorSet;
    private View mCustomView;
    private WebChromeClient.CustomViewCallback mCustomViewCallback;
    private RotateAnimation mRefreshAnimation;
    private List<String> mUrlList;
    private volatile boolean needToDestroyWebView;
    private RadialProgressView progressView;
    private String title;
    private String url;
    private FrameLayout video_view;
    private volatile boolean viewIsInit;
    private WebClient webClient;
    private FrameLayout webViewContainer;
    private volatile boolean webViewIsInit;

    public static boolean checkCanToPausedPlayGamePage() {
        return Instance != null;
    }

    public static DiscoveryJumpToPage toPage(String title, String url) {
        Instance = new DiscoveryJumpToPage();
        Bundle args = new Bundle();
        args.putString("title", title);
        args.putString(ImagesContract.URL, url);
        Instance.setArguments(args);
        return Instance;
    }

    public static DiscoveryJumpToPage toPausedPlayGamePage() {
        if (Instance == null) {
            throw new IllegalArgumentException("The static PlayGameActivity is null, please check it.");
        }
        return Instance;
    }

    public static void hideGameWebView(BaseFragment currentPage) {
        if (Instance == null) {
            return;
        }
        NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.folderWebView, new Object[0]);
        if (currentPage != null && !currentPage.isFinishing()) {
            currentPage.finishFragment();
        }
    }

    public static void destroyGameWebView() {
        if (Instance == null) {
            return;
        }
        if (Instance.agentWebView != null) {
            Instance.agentWebView.destroy();
        }
        Instance = null;
    }

    public static String getTitle() {
        if (Instance != null) {
            return Instance.title;
        }
        return "";
    }

    public static String getUrl() {
        if (Instance != null) {
            return Instance.url;
        }
        return "";
    }

    private DiscoveryJumpToPage() {
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onFragmentCreate() {
        if (getArguments() != null) {
            this.title = getArguments().getString("title");
            this.url = getArguments().getString(ImagesContract.URL);
        }
        if (TextUtils.isEmpty(this.url)) {
            return false;
        }
        return super.onFragmentCreate();
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        DragHelperFrameLayout dragHelperFrameLayout = (DragHelperFrameLayout) LayoutInflater.from(context).inflate(R.layout.activity_discovery_jump_to_page, (ViewGroup) null, false);
        this.dragHelperFrameLayout = dragHelperFrameLayout;
        this.fragmentView = dragHelperFrameLayout;
        this.fragmentView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        getParentActivity().setRequestedOrientation(7);
        initView(context);
        initWebView(false);
        if (this.containerGuideRoot != null && checkShowGuide()) {
            this.containerGuideRoot.setVisibility(checkShowGuide() ? 0 : 8);
        }
        return this.fragmentView;
    }

    private void initView(Context context) {
        if (this.viewIsInit || context == null) {
            return;
        }
        this.ivClose = (ImageView) this.fragmentView.findViewById(R.attr.ivClose);
        this.ivShowMenuDialog = (ImageView) this.fragmentView.findViewById(R.attr.ivShowMenuDialog);
        setInPreviewMode(true);
        this.actionBar.setAddToContainer(false);
        this.containerGuideRoot = this.fragmentView.findViewById(R.attr.containerGuideRoot);
        this.video_view = (FrameLayout) this.fragmentView.findViewById(R.attr.video_view);
        this.imgRefresh = (ImageView) this.fragmentView.findViewById(R.attr.img_refresh);
        this.containerMenu = this.fragmentView.findViewById(R.attr.containerMenu);
        this.dhfMenu = (DragHelperFrameLayout) this.fragmentView.findViewById(R.attr.dhfMenu);
        this.webViewContainer = (FrameLayout) this.fragmentView.findViewById(R.attr.containerWebView);
        RadialProgressView radialProgressView = (RadialProgressView) this.fragmentView.findViewById(R.attr.progressView);
        this.progressView = radialProgressView;
        radialProgressView.setSize(AndroidUtilities.dp(20.0f));
        this.progressView.setStrokeWidth(2.0f);
        this.progressView.setProgressColor(-1);
        this.ivClose.setOnClickListener(this);
        this.ivShowMenuDialog.setOnClickListener(this);
        this.imgRefresh.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.discoveryweb.DiscoveryJumpToPage.1
            @Override // android.view.View.OnClickListener
            public void onClick(View v) {
                DiscoveryJumpToPage.Instance.agentWebView.getUrlLoader().loadUrl(DiscoveryJumpToPage.this.url);
            }
        });
        this.fragmentView.findViewById(R.attr.btnPlayGameGuideKnown).setOnClickListener(this);
        DragHelperFrameLayout dragHelperFrameLayout = this.dragHelperFrameLayout;
        dragHelperFrameLayout.setViewDragCallBack(new DragCallBack(dragHelperFrameLayout, this.containerMenu) { // from class: im.uwrkaxlmjj.ui.hui.discoveryweb.DiscoveryJumpToPage.2
            @Override // im.uwrkaxlmjj.ui.hviews.dragView.DragCallBack
            public List<Rect> getNotchRectList() {
                WindowInsets windowInsets;
                DisplayCutout displayCutout;
                if (Build.VERSION.SDK_INT >= 28 && (windowInsets = DiscoveryJumpToPage.this.getParentActivity().getWindow().getDecorView().getRootWindowInsets()) != null && (displayCutout = windowInsets.getDisplayCutout()) != null) {
                    return displayCutout.getBoundingRects();
                }
                return super.getNotchRectList();
            }
        });
        DragHelperFrameLayout dragHelperFrameLayout2 = this.dragHelperFrameLayout;
        dragHelperFrameLayout2.setViewDragCallBack(new DragCallBack(dragHelperFrameLayout2, this.imgRefresh) { // from class: im.uwrkaxlmjj.ui.hui.discoveryweb.DiscoveryJumpToPage.3
            @Override // im.uwrkaxlmjj.ui.hviews.dragView.DragCallBack
            public List<Rect> getNotchRectList() {
                WindowInsets windowInsets;
                DisplayCutout displayCutout;
                if (Build.VERSION.SDK_INT >= 28 && (windowInsets = DiscoveryJumpToPage.this.getParentActivity().getWindow().getDecorView().getRootWindowInsets()) != null && (displayCutout = windowInsets.getDisplayCutout()) != null) {
                    return displayCutout.getBoundingRects();
                }
                return super.getNotchRectList();
            }
        });
        DragHelperFrameLayout dragHelperFrameLayout3 = this.dhfMenu;
        dragHelperFrameLayout3.setViewDragCallBack(new DragCallBack(dragHelperFrameLayout3, this.containerMenu) { // from class: im.uwrkaxlmjj.ui.hui.discoveryweb.DiscoveryJumpToPage.4
            @Override // im.uwrkaxlmjj.ui.hviews.dragView.DragCallBack
            public List<Rect> getNotchRectList() {
                WindowInsets windowInsets;
                DisplayCutout displayCutout;
                if (Build.VERSION.SDK_INT >= 28 && (windowInsets = DiscoveryJumpToPage.this.getParentActivity().getWindow().getDecorView().getRootWindowInsets()) != null && (displayCutout = windowInsets.getDisplayCutout()) != null) {
                    return displayCutout.getBoundingRects();
                }
                return super.getNotchRectList();
            }
        });
        changeSystemStatusBar(false);
        this.viewIsInit = true;
    }

    private void initWebView(boolean fromResume) {
        this.agentWebView = AgentWeb.with(getParentActivity()).setAgentWebParent(this.webViewContainer, new FrameLayout.LayoutParams(-1, -1)).useDefaultIndicator().createAgentWeb().ready().go(this.url);
        if (!fromResume) {
            refresh();
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onResume() {
        super.onResume();
        initView(getParentActivity());
        initWebView(true);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onPause() {
        super.onPause();
    }

    private void changeSystemStatusBar(boolean check) {
        if (Build.VERSION.SDK_INT >= 21) {
            if (!check) {
                this.fragmentView.setSystemUiVisibility(this.fragmentView.getSystemUiVisibility() | 4);
            } else {
                this.fragmentView.getSystemUiVisibility();
                this.fragmentView.setSystemUiVisibility(this.fragmentView.getSystemUiVisibility() | 4);
            }
        }
    }

    private void refresh() {
        String _url;
        if (isFinishing()) {
            return;
        }
        List<String> list = this.mUrlList;
        if (list != null && list.size() > 1) {
            List<String> list2 = this.mUrlList;
            _url = list2.get(list2.size() - 1);
        } else {
            _url = this.url;
        }
        if (_url == null) {
            return;
        }
        if (!_url.startsWith(DefaultWebClient.HTTP_SCHEME) && !_url.startsWith(DefaultWebClient.HTTPS_SCHEME)) {
            _url = DefaultWebClient.HTTP_SCHEME + _url;
        }
        this.agentWebView.getUrlLoader().loadUrl(_url);
    }

    private boolean canFinishThisPage() {
        AgentWeb agentWeb = this.agentWebView;
        return (agentWeb == null || agentWeb.back()) ? false : true;
    }

    public void finishThisPage() {
        this.needToDestroyWebView = true;
        finishFragment();
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

    @Override // android.view.View.OnClickListener
    public void onClick(View v) {
        int id = v.getId();
        if (id != R.attr.btnPlayGameGuideKnown) {
            if (id == R.attr.ivClose) {
                finishThisPage();
                return;
            } else {
                if (id == R.attr.ivShowMenuDialog) {
                    DiscoveryJumpMenuDialog dialog = new DiscoveryJumpMenuDialog(getParentActivity());
                    dialog.setOnItemClickListener(new RecyclerListView.OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.hui.discoveryweb.-$$Lambda$DiscoveryJumpToPage$9oFseD7n5L0yJ9fVhmZg_2JlK2g
                        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemClickListener
                        public final void onItemClick(View view, int i) {
                            this.f$0.lambda$onClick$0$DiscoveryJumpToPage(view, i);
                        }
                    });
                    showDialog(dialog);
                    return;
                }
                return;
            }
        }
        SharedPreferences preferences = getParentActivity().getSharedPreferences("DiscoveryJumpPage", 0);
        SharedPreferences.Editor editor = preferences.edit();
        editor.putBoolean("guide", false);
        editor.apply();
        View view = this.containerGuideRoot;
        if (view != null) {
            view.setVisibility(8);
        }
    }

    public /* synthetic */ void lambda$onClick$0$DiscoveryJumpToPage(View view, int position) {
        if (position == 0) {
            hideGameWebView(this);
        } else if (position == 1) {
            refresh();
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onRequestPermissionsResultFragment(int requestCode, String[] permissions, int[] grantResults) {
        ChromeClient chromeClient;
        if (requestCode != 99 || (chromeClient = this.chromeClient) == null) {
            return;
        }
        chromeClient.showRequestLocationPermissionDialog(permissions[0], chromeClient.mGeolocationPermissionsCallBack);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    protected void onDialogDismiss(Dialog dialog) {
        changeSystemStatusBar(false);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void saveSelfArgs(Bundle args) {
        super.saveSelfArgs(args);
        args.putString(ImagesContract.URL, this.url);
        args.putString("title", this.title);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void restoreSelfArgs(Bundle args) {
        super.restoreSelfArgs(args);
        this.title = args.getString("title");
        this.url = args.getString(ImagesContract.URL);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onBackPressed() {
        if (canFinishThisPage()) {
            finishThisPage();
            return false;
        }
        AgentWeb agentWeb = this.agentWebView;
        if (agentWeb != null && agentWeb.back()) {
            this.agentWebView.back();
            return false;
        }
        return super.onBackPressed();
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onActivityResultFragment(int requestCode, int resultCode, Intent data) {
        super.onActivityResultFragment(requestCode, resultCode, data);
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

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean canBeginSlide() {
        return false;
    }

    private boolean checkShowGuide() {
        SharedPreferences preferences = getParentActivity().getSharedPreferences("DiscoveryJumpPage", 0);
        return preferences.getBoolean("guide", true);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onFragmentDestroy() {
        if (this.needToDestroyWebView) {
            destroyGameWebView();
        }
        AnimatorSet animatorSet = this.mAnimatorSet;
        if (animatorSet != null) {
            try {
                animatorSet.cancel();
            } catch (Exception e) {
            }
            this.mAnimatorSet = null;
        }
        RotateAnimation rotateAnimation = this.mRefreshAnimation;
        if (rotateAnimation != null) {
            try {
                rotateAnimation.cancel();
            } catch (Exception e2) {
            }
            this.mRefreshAnimation = null;
        }
        super.onFragmentDestroy();
        List<String> list = this.mUrlList;
        if (list != null) {
            list.clear();
            this.mUrlList = null;
        }
        this.webClient = null;
        ChromeClient chromeClient = this.chromeClient;
        if (chromeClient != null) {
            chromeClient.fileChooserCallback = null;
            this.chromeClient.fileChooserCallback40 = null;
            this.chromeClient.mGeolocationPermissionsCallBack = null;
            this.chromeClient = null;
        }
        this.chromeClient = null;
        this.viewIsInit = false;
        this.webViewIsInit = false;
        if (getParentActivity() != null) {
            getParentActivity().setRequestedOrientation(1);
        }
    }

    private class WebClient extends WebViewClient {
        private WebClient() {
        }

        @Override // android.webkit.WebViewClient
        public boolean onRenderProcessGone(WebView view, RenderProcessGoneDetail detail) {
            Log.d("bond", "WebClient onRenderProcessGone  , detail = " + detail);
            view.loadUrl(view.getUrl());
            return true;
        }

        @Override // android.webkit.WebViewClient
        public void onLoadResource(WebView view, String url) {
            super.onLoadResource(view, url);
        }

        @Override // android.webkit.WebViewClient
        public void onReceivedSslError(WebView view, SslErrorHandler handler, SslError error) {
            handler.proceed();
        }

        @Override // android.webkit.WebViewClient
        public boolean shouldOverrideUrlLoading(WebView view, String url) {
            Log.d("bond", "WebClient shouldOverrideUrlLoading  , url = " + url);
            if (DiscoveryJumpToPage.this.isFinishing()) {
                return false;
            }
            if (url != null) {
                try {
                    if (!url.startsWith(ProxyInfo.TYPE_HTTPS) && !url.startsWith("http") && DiscoveryJumpToPage.this.getParentActivity() != null) {
                        Intent intent = new Intent("android.intent.action.VIEW", Uri.parse(url));
                        intent.putExtra("create_new_tab", true);
                        intent.putExtra("com.android.browser.application_id", DiscoveryJumpToPage.this.getParentActivity().getPackageName());
                        DiscoveryJumpToPage.this.getParentActivity().startActivity(intent);
                        return true;
                    }
                } catch (Throwable e) {
                    FileLog.e(DiscoveryJumpToPage.class.getName(), e);
                    ToastUtils.show(R.string.NoAppCanHandleThis);
                    return true;
                }
            }
            try {
                if (DiscoveryJumpToPage.this.mUrlList != null) {
                    if (DiscoveryJumpToPage.this.mUrlList.contains(url) && !((String) DiscoveryJumpToPage.this.mUrlList.get(DiscoveryJumpToPage.this.mUrlList.size() - 1)).equals(url)) {
                        DiscoveryJumpToPage.this.mUrlList.remove(url);
                    }
                    DiscoveryJumpToPage.this.mUrlList.add(url);
                }
            } catch (Exception e1) {
                FileLog.e(DiscoveryJumpToPage.class.getName() + " shouldOverrideUrlLoading error: " + e1.getMessage());
            }
            view.loadUrl(url);
            return true;
        }

        @Override // android.webkit.WebViewClient
        public void onPageStarted(WebView view, String url, Bitmap favicon) {
            super.onPageStarted(view, url, favicon);
            if (!DiscoveryJumpToPage.this.isFinishing()) {
                if (DiscoveryJumpToPage.this.ivShowMenuDialog != null && DiscoveryJumpToPage.this.ivShowMenuDialog.getVisibility() != 8) {
                    DiscoveryJumpToPage.this.ivShowMenuDialog.setVisibility(8);
                }
                if (DiscoveryJumpToPage.this.progressView != null && DiscoveryJumpToPage.this.progressView.getVisibility() != 0) {
                    DiscoveryJumpToPage.this.progressView.setVisibility(0);
                }
            }
        }

        @Override // android.webkit.WebViewClient
        public void onPageFinished(WebView view, String url) {
            super.onPageFinished(view, url);
            if (!DiscoveryJumpToPage.this.isFinishing()) {
                if (DiscoveryJumpToPage.this.progressView != null && DiscoveryJumpToPage.this.progressView.getVisibility() != 8) {
                    DiscoveryJumpToPage.this.progressView.setVisibility(8);
                }
                if (DiscoveryJumpToPage.this.ivShowMenuDialog != null && DiscoveryJumpToPage.this.ivShowMenuDialog.getVisibility() != 0) {
                    DiscoveryJumpToPage.this.ivShowMenuDialog.setVisibility(0);
                }
            }
        }

        @Override // android.webkit.WebViewClient
        public void onReceivedError(WebView view, int errorCode, String description, String failingUrl) {
            FileLog.e(DiscoveryJumpToPage.class.getName() + " onReceivedError: code:" + errorCode + ", des:" + description + ", u:" + failingUrl);
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
        public boolean onConsoleMessage(ConsoleMessage consoleMessage) {
            Log.d("bond", consoleMessage.message() + " -- From line " + consoleMessage.lineNumber() + " of " + consoleMessage.sourceId());
            return true;
        }

        @Override // android.webkit.WebChromeClient
        public void onShowCustomView(View view, WebChromeClient.CustomViewCallback callback) {
            DiscoveryJumpToPage.this.video_view.addView(view);
            DiscoveryJumpToPage.this.video_view.setVisibility(0);
            DiscoveryJumpToPage.this.mCustomView = view;
            DiscoveryJumpToPage.this.webViewContainer.setVisibility(8);
            DiscoveryJumpToPage.this.getParentActivity().setRequestedOrientation(0);
        }

        @Override // android.webkit.WebChromeClient
        public void onHideCustomView() {
            if (DiscoveryJumpToPage.this.mCustomView == null) {
                return;
            }
            DiscoveryJumpToPage.this.mCustomView.setVisibility(8);
            DiscoveryJumpToPage.this.video_view.removeView(DiscoveryJumpToPage.this.mCustomView);
            DiscoveryJumpToPage.this.mCustomView = null;
            DiscoveryJumpToPage.this.video_view.setVisibility(8);
            DiscoveryJumpToPage.this.webViewContainer.setVisibility(0);
            if (DiscoveryJumpToPage.this.mCustomViewCallback != null) {
                DiscoveryJumpToPage.this.mCustomViewCallback.onCustomViewHidden();
                DiscoveryJumpToPage.this.mCustomViewCallback = null;
            }
            DiscoveryJumpToPage.this.getParentActivity().setRequestedOrientation(1);
        }

        @Override // android.webkit.WebChromeClient
        public boolean onCreateWindow(WebView view, boolean isDialog, boolean isUserGesture, Message resultMsg) {
            WebView myWeb = new WebView(DiscoveryJumpToPage.this.getParentActivity());
            Message href = view.getHandler().obtainMessage();
            view.requestFocusNodeHref(href);
            String url = href.getData().getString(ImagesContract.URL);
            myWeb.loadUrl(url);
            return true;
        }

        @Override // android.webkit.WebChromeClient
        public void onReceivedTitle(WebView view, String title) {
            if (DiscoveryJumpToPage.this.isFinishing()) {
            }
        }

        @Override // android.webkit.WebChromeClient
        public boolean onJsAlert(WebView view, String url, String message, JsResult result) {
            if (DiscoveryJumpToPage.this.isFinishing()) {
                return false;
            }
            AlertDialog.Builder builder = new AlertDialog.Builder(DiscoveryJumpToPage.this.getParentActivity());
            builder.setMessage(message);
            DiscoveryJumpToPage.this.showDialog(builder.create());
            return true;
        }

        @Override // android.webkit.WebChromeClient
        public boolean onJsConfirm(WebView view, String url, String message, final JsResult result) {
            if (DiscoveryJumpToPage.this.isFinishing()) {
                return false;
            }
            AlertDialog.Builder builder = new AlertDialog.Builder(DiscoveryJumpToPage.this.getParentActivity());
            builder.setMessage(message);
            builder.setPositiveButton(LocaleController.getString(R.string.OK), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.discoveryweb.-$$Lambda$DiscoveryJumpToPage$ChromeClient$Gas6s5FIfNxNDddUO5RpLhynLYM
                @Override // android.content.DialogInterface.OnClickListener
                public final void onClick(DialogInterface dialogInterface, int i) {
                    result.confirm();
                }
            });
            builder.setNegativeButton(LocaleController.getString(R.string.Cancel), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.discoveryweb.-$$Lambda$DiscoveryJumpToPage$ChromeClient$LyiGDbVcsGlNGSe2GddApONi_kg
                @Override // android.content.DialogInterface.OnClickListener
                public final void onClick(DialogInterface dialogInterface, int i) {
                    result.cancel();
                }
            });
            DiscoveryJumpToPage.this.showDialog(builder.create());
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
            if (DiscoveryJumpToPage.this.isFinishing() || this.mIsRequestingLocationPermission) {
                return;
            }
            this.mIsRequestingLocationPermission = true;
            this.mGeolocationPermissionsCallBack = callback;
            if (ContextCompat.checkSelfPermission(DiscoveryJumpToPage.this.getParentActivity(), origin) != 0) {
                String[] per = {origin};
                ActivityCompat.requestPermissions(DiscoveryJumpToPage.this.getParentActivity(), per, 99);
            } else {
                showRequestLocationPermissionDialog(origin, callback);
            }
        }

        @Override // android.webkit.WebChromeClient
        public void onPermissionRequest(PermissionRequest request) {
            if (!DiscoveryJumpToPage.this.isFinishing() && Build.VERSION.SDK_INT >= 21) {
                try {
                    request.grant(request.getResources());
                } catch (Exception e) {
                }
            }
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void showRequestLocationPermissionDialog(final String origin, final GeolocationPermissions.Callback callback) {
            if (!DiscoveryJumpToPage.this.isFinishing() && callback != null) {
                DiscoveryJumpToPage.this.showDialog(LocaleController.getString(R.string.RequestPermissionOfLocationDoYouAgreement), false, false, LocaleController.getString(R.string.Decline), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.discoveryweb.-$$Lambda$DiscoveryJumpToPage$ChromeClient$IzCSUCd2PH4qO9V0hJfSujrxXmw
                    @Override // android.content.DialogInterface.OnClickListener
                    public final void onClick(DialogInterface dialogInterface, int i) {
                        this.f$0.lambda$showRequestLocationPermissionDialog$2$DiscoveryJumpToPage$ChromeClient(callback, origin, dialogInterface, i);
                    }
                }, LocaleController.getString(R.string.Agree), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.discoveryweb.-$$Lambda$DiscoveryJumpToPage$ChromeClient$kqdBv_at0QaK8JfIiIC2YQUYp1U
                    @Override // android.content.DialogInterface.OnClickListener
                    public final void onClick(DialogInterface dialogInterface, int i) {
                        this.f$0.lambda$showRequestLocationPermissionDialog$3$DiscoveryJumpToPage$ChromeClient(callback, origin, dialogInterface, i);
                    }
                }, new DialogInterface.OnCancelListener() { // from class: im.uwrkaxlmjj.ui.hui.discoveryweb.-$$Lambda$DiscoveryJumpToPage$ChromeClient$_1a2Mimeani1dH5jp854KfLduGA
                    @Override // android.content.DialogInterface.OnCancelListener
                    public final void onCancel(DialogInterface dialogInterface) {
                        this.f$0.lambda$showRequestLocationPermissionDialog$4$DiscoveryJumpToPage$ChromeClient(callback, origin, dialogInterface);
                    }
                }, new DialogInterface.OnDismissListener() { // from class: im.uwrkaxlmjj.ui.hui.discoveryweb.-$$Lambda$DiscoveryJumpToPage$ChromeClient$Spaej43_QJvuMpED3e3iGomJEJc
                    @Override // android.content.DialogInterface.OnDismissListener
                    public final void onDismiss(DialogInterface dialogInterface) {
                        this.f$0.lambda$showRequestLocationPermissionDialog$5$DiscoveryJumpToPage$ChromeClient(dialogInterface);
                    }
                });
            }
        }

        public /* synthetic */ void lambda$showRequestLocationPermissionDialog$2$DiscoveryJumpToPage$ChromeClient(GeolocationPermissions.Callback callback, String origin, DialogInterface dialog, int which) {
            if (callback != null) {
                callback.invoke(origin, false, false);
            }
            this.mIsRequestingLocationPermission = false;
        }

        public /* synthetic */ void lambda$showRequestLocationPermissionDialog$3$DiscoveryJumpToPage$ChromeClient(GeolocationPermissions.Callback callback, String origin, DialogInterface dialog, int which) {
            if (callback != null) {
                callback.invoke(origin, true, false);
            }
            this.mIsRequestingLocationPermission = false;
        }

        public /* synthetic */ void lambda$showRequestLocationPermissionDialog$4$DiscoveryJumpToPage$ChromeClient(GeolocationPermissions.Callback callback, String origin, DialogInterface dialog) {
            if (callback != null) {
                callback.invoke(origin, false, false);
            }
            this.mIsRequestingLocationPermission = false;
        }

        public /* synthetic */ void lambda$showRequestLocationPermissionDialog$5$DiscoveryJumpToPage$ChromeClient(DialogInterface dialog) {
            this.mIsRequestingLocationPermission = false;
        }

        public void openFileChooser(ValueCallback<Uri> valueCallback) {
            this.fileChooserCallback40 = valueCallback;
            DiscoveryJumpToPage.this.openFileChoosers();
        }

        public void openFileChooser(ValueCallback<Uri> valueCallback, String acceptType) {
            this.fileChooserCallback40 = valueCallback;
            DiscoveryJumpToPage.this.openFileChoosers();
        }

        public void openFileChooser(ValueCallback<Uri> valueCallback, String acceptType, String capture) {
            this.fileChooserCallback40 = valueCallback;
            DiscoveryJumpToPage.this.openFileChoosers();
        }

        @Override // android.webkit.WebChromeClient
        public boolean onShowFileChooser(WebView webView, ValueCallback<Uri[]> filePathCallback, WebChromeClient.FileChooserParams fileChooserParams) {
            this.fileChooserCallback = filePathCallback;
            DiscoveryJumpToPage.this.openFileChoosers();
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
