package im.uwrkaxlmjj.ui.hui;

import android.graphics.Bitmap;
import android.os.Bundle;
import android.text.TextUtils;
import android.view.ViewParent;
import android.view.animation.Animation;
import android.view.animation.AnimationUtils;
import android.view.animation.LinearInterpolator;
import android.webkit.WebChromeClient;
import android.webkit.WebResourceRequest;
import android.webkit.WebResourceResponse;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import androidx.appcompat.app.AppCompatActivity;
import com.google.android.gms.common.internal.ImagesContract;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenu;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenuItem;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class WebViewAppCompatActivity extends AppCompatActivity {
    private ActionBar actionBar;
    private ActionBarMenu actionBarMenu;
    private ActionBarMenuItem menuItem;
    private ActionBarMenuItem refreshMenuItem;
    private LinearLayout root;
    private String url;
    private WebView webView;

    @Override // androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    protected void onCreate(Bundle savedInstanceState) {
        requestWindowFeature(1);
        setTheme(2131755390);
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_webview_compat);
        this.root = (LinearLayout) findViewById(R.attr.root);
        this.webView = (WebView) findViewById(R.attr.webView);
        this.root.setBackgroundColor(-1);
        ActionBar actionBar = new ActionBar(this);
        this.actionBar = actionBar;
        actionBar.setBackgroundColor(-1);
        this.actionBar.setItemsBackgroundColor(-12554860, false);
        this.actionBar.setItemsBackgroundColor(-986896, true);
        this.actionBar.setItemsColor(-16777216, false);
        this.actionBar.setItemsColor(-16777216, true);
        this.actionBar.setOccupyStatusBar(true);
        this.actionBar.setTitle(LocaleController.getString("Chats", R.string.Chats));
        this.actionBar.setCastShadows(true);
        this.actionBar.setBackButtonImage(R.id.ic_back);
        ActionBarMenu actionBarMenuCreateMenu = this.actionBar.createMenu();
        this.actionBarMenu = actionBarMenuCreateMenu;
        this.refreshMenuItem = actionBarMenuCreateMenu.addItem(1, R.drawable.ic_againinline);
        ActionBarMenuItem actionBarMenuItemAddItem = this.actionBarMenu.addItem(2, R.drawable.bar_right_menu);
        this.menuItem = actionBarMenuItemAddItem;
        actionBarMenuItemAddItem.addSubItem(3, R.drawable.msg_openin, LocaleController.getString("OpenInExternalApp", R.string.OpenInExternalApp));
        this.menuItem.addSubItem(4, R.drawable.msg_copy, LocaleController.getString("CopyLink", R.string.CopyLink));
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.hui.WebViewAppCompatActivity.1
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                super.onItemClick(id);
                if (id == -1) {
                    WebViewAppCompatActivity.this.finish();
                } else if (id == 1 && !TextUtils.isEmpty(WebViewAppCompatActivity.this.url) && WebViewAppCompatActivity.this.webView != null) {
                    WebViewAppCompatActivity.this.webView.loadUrl(WebViewAppCompatActivity.this.url);
                }
            }
        });
        this.root.addView(this.actionBar, 0, LayoutHelper.createLinear(-1, -2));
        WebSettings settings = this.webView.getSettings();
        settings.setJavaScriptEnabled(true);
        settings.setUseWideViewPort(true);
        settings.setSupportZoom(true);
        settings.setLoadWithOverviewMode(true);
        settings.setTextZoom(100);
        this.webView.setFocusable(true);
        this.webView.setWebChromeClient(new WebChromeClient() { // from class: im.uwrkaxlmjj.ui.hui.WebViewAppCompatActivity.2
            @Override // android.webkit.WebChromeClient
            public void onReceivedTitle(WebView view, String title) {
                super.onReceivedTitle(view, title);
                if (WebViewAppCompatActivity.this.actionBar != null && !TextUtils.isEmpty(title)) {
                    WebViewAppCompatActivity.this.actionBar.setTitle(title);
                }
            }
        });
        this.webView.setWebViewClient(new WebViewClient() { // from class: im.uwrkaxlmjj.ui.hui.WebViewAppCompatActivity.3
            @Override // android.webkit.WebViewClient
            public boolean shouldOverrideUrlLoading(WebView view, String url) {
                WebViewAppCompatActivity.this.url = url;
                view.loadUrl(url);
                return false;
            }

            @Override // android.webkit.WebViewClient
            public void onReceivedError(WebView view, int errorCode, String description, String failingUrl) {
                super.onReceivedError(view, errorCode, description, failingUrl);
                FileLog.e("WebViewAppCompatActivity ===> WebViewClient onReceivedError , errorCode = " + errorCode + " , description = " + description);
            }

            @Override // android.webkit.WebViewClient
            public void onReceivedHttpError(WebView view, WebResourceRequest request, WebResourceResponse errorResponse) {
                super.onReceivedHttpError(view, request, errorResponse);
            }

            @Override // android.webkit.WebViewClient
            public void onPageStarted(WebView view, String url, Bitmap favicon) {
                super.onPageStarted(view, url, favicon);
                if (WebViewAppCompatActivity.this.refreshMenuItem != null && WebViewAppCompatActivity.this.refreshMenuItem.getAnimation() == null) {
                    Animation rotate = AnimationUtils.loadAnimation(WebViewAppCompatActivity.this, R.anim.rotate_360_forever);
                    rotate.setInterpolator(new LinearInterpolator());
                    WebViewAppCompatActivity.this.refreshMenuItem.startAnimation(rotate);
                }
            }

            @Override // android.webkit.WebViewClient
            public void onPageFinished(WebView view, String url) {
                super.onPageFinished(view, url);
                if (WebViewAppCompatActivity.this.refreshMenuItem != null) {
                    WebViewAppCompatActivity.this.refreshMenuItem.clearAnimation();
                }
            }

            @Override // android.webkit.WebViewClient
            public void onLoadResource(WebView view, String url) {
                super.onLoadResource(view, url);
            }
        });
    }

    @Override // androidx.appcompat.app.AppCompatActivity, androidx.fragment.app.FragmentActivity, android.app.Activity
    protected void onStart() {
        super.onStart();
        String stringExtra = getIntent().getStringExtra(ImagesContract.URL);
        this.url = stringExtra;
        if (TextUtils.isEmpty(stringExtra)) {
            finish();
            return;
        }
        if (this.url.contains("file")) {
            ActionBarMenuItem actionBarMenuItem = this.refreshMenuItem;
            if (actionBarMenuItem != null) {
                actionBarMenuItem.setVisibility(8);
            }
            ActionBarMenuItem actionBarMenuItem2 = this.menuItem;
            if (actionBarMenuItem2 != null) {
                actionBarMenuItem2.setVisibility(8);
            }
        }
        this.webView.loadUrl(this.url);
    }

    @Override // androidx.fragment.app.FragmentActivity, android.app.Activity
    protected void onResume() {
        super.onResume();
        WebView webView = this.webView;
        if (webView != null) {
            webView.onResume();
        }
    }

    @Override // androidx.fragment.app.FragmentActivity, android.app.Activity
    protected void onPause() {
        super.onPause();
        WebView webView = this.webView;
        if (webView != null) {
            webView.onPause();
        }
    }

    @Override // androidx.activity.ComponentActivity, android.app.Activity
    public void onBackPressed() {
        WebView webView = this.webView;
        if (webView != null && webView.canGoBack()) {
            this.webView.goBack();
        } else {
            super.onBackPressed();
        }
    }

    @Override // androidx.appcompat.app.AppCompatActivity, androidx.fragment.app.FragmentActivity, android.app.Activity
    protected void onDestroy() {
        super.onDestroy();
        this.url = null;
        LinearLayout linearLayout = this.root;
        if (linearLayout != null) {
            linearLayout.removeAllViews();
            this.root.removeAllViewsInLayout();
            this.root = null;
        }
        ActionBarMenuItem actionBarMenuItem = this.refreshMenuItem;
        if (actionBarMenuItem != null) {
            actionBarMenuItem.removeAllViews();
            this.refreshMenuItem.removeAllViewsInLayout();
            this.refreshMenuItem = null;
        }
        ActionBar actionBar = this.actionBar;
        if (actionBar != null) {
            actionBar.removeAllViews();
            this.actionBar.removeAllViewsInLayout();
            this.actionBar = null;
        }
        try {
            this.webView.setLayerType(0, null);
            ViewParent parent = this.webView.getParent();
            if (parent != null) {
                ((FrameLayout) parent).removeView(this.webView);
            }
            this.webView.stopLoading();
            this.webView.loadUrl("about:blank");
            this.webView.destroy();
            this.webView = null;
        } catch (Exception e) {
            FileLog.e(e);
        }
    }
}
