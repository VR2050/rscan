package im.uwrkaxlmjj.ui.wallet;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.AnimatorSet;
import android.animation.ObjectAnimator;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.net.Uri;
import android.os.Build;
import android.text.TextUtils;
import android.view.View;
import android.view.ViewParent;
import android.webkit.CookieManager;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.FrameLayout;
import com.google.android.exoplayer2.C;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ApplicationLoader;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenu;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenuItem;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.components.ContextProgressView;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.hui.wallet_public.utils.WalletDialogUtil;
import im.uwrkaxlmjj.ui.wallet.WalletRechargeH5Activity;
import java.util.Timer;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class WalletRechargeH5Activity extends BaseFragment {
    private static final int LOADING = 1;
    private String currentUrl;
    private boolean loadStats;
    private int mCount;
    private boolean mIsDestroy;
    private int mPayWay;
    private int mRequestToken;
    private Timer mTimer;
    private boolean mTimerIsRunning;
    private ActionBarMenuItem progressItem;
    private ContextProgressView progressView;
    private WebView webView;

    public WalletRechargeH5Activity(int payWay, String url) {
        this.mPayWay = payWay;
        this.currentUrl = url;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        this.swipeBackEnabled = false;
        this.actionBar.setBackButtonImage(R.id.ic_back);
        this.actionBar.setAllowOverlayTitle(true);
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.wallet.WalletRechargeH5Activity.1
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                if (id == -1) {
                    WalletRechargeH5Activity.this.finishFragment();
                }
            }
        });
        ActionBarMenu menu = this.actionBar.createMenu();
        this.progressItem = menu.addItemWithWidth(1, R.drawable.ic_ab_other, AndroidUtilities.dp(54.0f));
        this.actionBar.setTitle(LocaleController.getString(R.string.redpacket_go_recharge));
        ContextProgressView contextProgressView = new ContextProgressView(context, 3);
        this.progressView = contextProgressView;
        this.progressItem.addView(contextProgressView, LayoutHelper.createFrame(-1, -1.0f));
        this.progressView.setAlpha(1.0f);
        this.progressView.setScaleX(1.0f);
        this.progressView.setScaleY(1.0f);
        this.progressView.setVisibility(0);
        this.progressItem.getContentView().setVisibility(8);
        this.progressItem.setEnabled(false);
        WebView webView = new WebView(context);
        this.webView = webView;
        webView.getSettings().setJavaScriptEnabled(true);
        this.webView.getSettings().setDomStorageEnabled(true);
        this.webView.getSettings().setTextZoom(100);
        this.fragmentView = new FrameLayout(context);
        FrameLayout frameLayout = (FrameLayout) this.fragmentView;
        if (Build.VERSION.SDK_INT >= 19) {
            this.webView.setLayerType(2, null);
        }
        if (Build.VERSION.SDK_INT >= 21) {
            this.webView.getSettings().setMixedContentMode(0);
            CookieManager cookieManager = CookieManager.getInstance();
            cookieManager.setAcceptThirdPartyCookies(this.webView, true);
        }
        this.webView.setWebViewClient(new AnonymousClass2());
        frameLayout.addView(this.webView, LayoutHelper.createFrame(-1, -1.0f));
        return this.fragmentView;
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.wallet.WalletRechargeH5Activity$2, reason: invalid class name */
    class AnonymousClass2 extends WebViewClient {
        AnonymousClass2() {
        }

        private boolean isInternalUrl(String url) {
            if (TextUtils.isEmpty(url)) {
                return false;
            }
            Uri uri = Uri.parse(url);
            if (!url.startsWith("alipays:") && !url.startsWith("alipay")) {
                return false;
            }
            try {
                Intent intent = new Intent("android.intent.action.VIEW", uri);
                intent.addFlags(C.ENCODING_PCM_MU_LAW);
                ApplicationLoader.applicationContext.startActivity(intent);
                return true;
            } catch (Exception e) {
                WalletDialogUtil.showWalletDialog(WalletRechargeH5Activity.this.getParentActivity(), LocaleController.getString(R.string.NotInstallAliPayAppTips), LocaleController.getString(R.string.InstallImmediate), false, null, new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.wallet.-$$Lambda$WalletRechargeH5Activity$2$MOBdPq_96hmL44GYTf21S0FTqYo
                    @Override // android.content.DialogInterface.OnClickListener
                    public final void onClick(DialogInterface dialogInterface, int i) {
                        WalletRechargeH5Activity.AnonymousClass2.lambda$isInternalUrl$0(dialogInterface, i);
                    }
                }, null);
                return true;
            }
        }

        static /* synthetic */ void lambda$isInternalUrl$0(DialogInterface dialog, int which) {
            try {
                Intent intent = new Intent("android.intent.action.VIEW", Uri.parse("https://d.alipay.com"));
                intent.addFlags(C.ENCODING_PCM_MU_LAW);
                ApplicationLoader.applicationContext.startActivity(intent);
            } catch (Exception e1) {
                FileLog.e(e1);
            }
        }

        @Override // android.webkit.WebViewClient
        public void onLoadResource(WebView view, String url) {
            if (isInternalUrl(url)) {
                return;
            }
            super.onLoadResource(view, url);
        }

        @Override // android.webkit.WebViewClient
        public boolean shouldOverrideUrlLoading(WebView view, String url) {
            if (!isInternalUrl(url)) {
                WalletRechargeH5Activity.this.webView.loadUrl(url);
            }
            return super.shouldOverrideUrlLoading(view, url);
        }

        @Override // android.webkit.WebViewClient
        public void onPageFinished(WebView view, String url) {
            super.onPageFinished(view, url);
            if (WalletRechargeH5Activity.this.progressItem != null && WalletRechargeH5Activity.this.progressItem.getVisibility() == 0) {
                AnimatorSet animatorSet = new AnimatorSet();
                animatorSet.playTogether(ObjectAnimator.ofFloat(WalletRechargeH5Activity.this.progressView, "scaleX", 1.0f, 0.1f), ObjectAnimator.ofFloat(WalletRechargeH5Activity.this.progressView, "scaleY", 1.0f, 0.1f), ObjectAnimator.ofFloat(WalletRechargeH5Activity.this.progressView, "alpha", 1.0f, 0.0f));
                animatorSet.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.wallet.WalletRechargeH5Activity.2.1
                    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                    public void onAnimationEnd(Animator animator) {
                        WalletRechargeH5Activity.this.progressItem.setVisibility(4);
                    }
                });
                animatorSet.setDuration(150L);
                animatorSet.start();
            }
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onBackPressed() {
        if (this.webView.canGoBack()) {
            this.webView.goBack();
            return false;
        }
        return super.onBackPressed();
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onResume() {
        super.onResume();
        WebView webView = this.webView;
        if (webView != null) {
            webView.onResume();
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onPause() {
        super.onPause();
        WebView webView = this.webView;
        if (webView != null) {
            webView.onPause();
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onFragmentDestroy() {
        this.mIsDestroy = true;
        super.onFragmentDestroy();
        this.webView.setLayerType(0, null);
        try {
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

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    protected void onTransitionAnimationEnd(boolean isOpen, boolean backward) {
        WebView webView;
        if (isOpen && !backward && (webView = this.webView) != null) {
            webView.loadUrl(this.currentUrl);
        }
    }
}
