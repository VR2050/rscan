package im.uwrkaxlmjj.ui;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.AnimatorSet;
import android.animation.ObjectAnimator;
import android.app.Activity;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.Uri;
import android.os.Build;
import android.text.TextUtils;
import android.view.View;
import android.view.ViewParent;
import android.webkit.CookieManager;
import android.webkit.JavascriptInterface;
import android.webkit.WebChromeClient;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.FrameLayout;
import com.just.agentweb.DefaultWebClient;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ApplicationLoader;
import im.uwrkaxlmjj.messenger.BuildVars;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MessageObject;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.Utilities;
import im.uwrkaxlmjj.messenger.browser.Browser;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.SerializedData;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenu;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenuItem;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.actionbar.ThemeDescription;
import im.uwrkaxlmjj.ui.components.ContextProgressView;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.components.ShareAlert;
import java.net.URLEncoder;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class WebviewActivity extends BaseFragment {
    private static final int TYPE_GAME = 0;
    private static final int TYPE_NONE = -1;
    private static final int TYPE_STAT = 1;
    private static final int open_in = 2;
    private static final int share = 1;
    private String currentBot;
    private long currentDialogId;
    private String currentGame;
    private MessageObject currentMessageObject;
    private String currentUrl;
    private String linkToCopy;
    private boolean loadStats;
    private String mTitle;
    private ActionBarMenuItem progressItem;
    private ContextProgressView progressView;
    private String short_param;
    private int type;
    public Runnable typingRunnable;
    private WebView webView;

    /* JADX INFO: Access modifiers changed from: private */
    class WebviewProxy {
        private WebviewProxy() {
        }

        @JavascriptInterface
        public void postEvent(final String eventName, String eventData) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$WebviewActivity$WebviewProxy$P_zh_vR1uyECHLlyNb298cWAcRY
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$postEvent$0$WebviewActivity$WebviewProxy(eventName);
                }
            });
        }

        public /* synthetic */ void lambda$postEvent$0$WebviewActivity$WebviewProxy(String eventName) {
            if (WebviewActivity.this.getParentActivity() == null) {
                return;
            }
            if (BuildVars.LOGS_ENABLED) {
                FileLog.d(eventName);
            }
            byte b = -1;
            int iHashCode = eventName.hashCode();
            if (iHashCode != -1788360622) {
                if (iHashCode == 406539826 && eventName.equals("share_score")) {
                    b = 1;
                }
            } else if (eventName.equals("share_game")) {
                b = 0;
            }
            if (b == 0) {
                WebviewActivity.this.currentMessageObject.messageOwner.with_my_score = false;
            } else if (b == 1) {
                WebviewActivity.this.currentMessageObject.messageOwner.with_my_score = true;
            }
            WebviewActivity webviewActivity = WebviewActivity.this;
            webviewActivity.showDialog(ShareAlert.createShareAlert(webviewActivity.getParentActivity(), WebviewActivity.this.currentMessageObject, null, false, WebviewActivity.this.linkToCopy, false));
        }
    }

    public WebviewActivity(String url, String botName, String gameName, String startParam, MessageObject messageObject) {
        String str;
        this.typingRunnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.WebviewActivity.1
            @Override // java.lang.Runnable
            public void run() {
                if (WebviewActivity.this.currentMessageObject != null && WebviewActivity.this.getParentActivity() != null && WebviewActivity.this.typingRunnable != null) {
                    MessagesController.getInstance(WebviewActivity.this.currentAccount).sendTyping(WebviewActivity.this.currentMessageObject.getDialogId(), 6, 0);
                    AndroidUtilities.runOnUIThread(WebviewActivity.this.typingRunnable, 25000L);
                }
            }
        };
        this.currentUrl = url;
        this.currentBot = botName;
        this.currentGame = gameName;
        this.currentMessageObject = messageObject;
        this.short_param = startParam;
        StringBuilder sb = new StringBuilder();
        sb.append(DefaultWebClient.HTTPS_SCHEME);
        sb.append(MessagesController.getInstance(this.currentAccount).linkPrefix);
        sb.append("/");
        sb.append(this.currentBot);
        if (TextUtils.isEmpty(startParam)) {
            str = "";
        } else {
            str = "?game=" + startParam;
        }
        sb.append(str);
        this.linkToCopy = sb.toString();
        this.type = 0;
    }

    public WebviewActivity(String statUrl, long did) {
        this.typingRunnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.WebviewActivity.1
            @Override // java.lang.Runnable
            public void run() {
                if (WebviewActivity.this.currentMessageObject != null && WebviewActivity.this.getParentActivity() != null && WebviewActivity.this.typingRunnable != null) {
                    MessagesController.getInstance(WebviewActivity.this.currentAccount).sendTyping(WebviewActivity.this.currentMessageObject.getDialogId(), 6, 0);
                    AndroidUtilities.runOnUIThread(WebviewActivity.this.typingRunnable, 25000L);
                }
            }
        };
        this.currentUrl = statUrl;
        this.currentDialogId = did;
        this.type = 1;
    }

    public WebviewActivity(String url, String title) {
        this.typingRunnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.WebviewActivity.1
            @Override // java.lang.Runnable
            public void run() {
                if (WebviewActivity.this.currentMessageObject != null && WebviewActivity.this.getParentActivity() != null && WebviewActivity.this.typingRunnable != null) {
                    MessagesController.getInstance(WebviewActivity.this.currentAccount).sendTyping(WebviewActivity.this.currentMessageObject.getDialogId(), 6, 0);
                    AndroidUtilities.runOnUIThread(WebviewActivity.this.typingRunnable, 25000L);
                }
            }
        };
        this.currentUrl = url;
        this.mTitle = title;
        this.type = -1;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onFragmentDestroy() {
        super.onFragmentDestroy();
        AndroidUtilities.cancelRunOnUIThread(this.typingRunnable);
        this.webView.setLayerType(0, null);
        this.typingRunnable = null;
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
    public View createView(Context context) {
        this.swipeBackEnabled = false;
        this.actionBar.setBackButtonImage(R.id.ic_back);
        this.actionBar.setAllowOverlayTitle(true);
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.WebviewActivity.2
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                if (id == -1) {
                    WebviewActivity.this.finishFragment();
                    return;
                }
                if (id == 1) {
                    if (WebviewActivity.this.currentMessageObject != null) {
                        WebviewActivity.this.currentMessageObject.messageOwner.with_my_score = false;
                        WebviewActivity webviewActivity = WebviewActivity.this;
                        webviewActivity.showDialog(ShareAlert.createShareAlert(webviewActivity.getParentActivity(), WebviewActivity.this.currentMessageObject, null, false, WebviewActivity.this.linkToCopy, false));
                        return;
                    }
                    return;
                }
                if (id == 2) {
                    WebviewActivity.openGameInBrowser(WebviewActivity.this.currentUrl, WebviewActivity.this.currentMessageObject, WebviewActivity.this.getParentActivity(), WebviewActivity.this.short_param, WebviewActivity.this.currentBot);
                }
            }
        });
        ActionBarMenu menu = this.actionBar.createMenu();
        this.progressItem = menu.addItemWithWidth(1, R.drawable.share, AndroidUtilities.dp(54.0f));
        int i = this.type;
        if (i == 0) {
            ActionBarMenuItem menuItem = menu.addItem(0, R.drawable.ic_ab_other);
            menuItem.addSubItem(2, R.drawable.msg_openin, LocaleController.getString("OpenInExternalApp", R.string.OpenInExternalApp));
            this.actionBar.setTitle(this.currentGame);
            this.actionBar.setSubtitle("@" + this.currentBot);
            ContextProgressView contextProgressView = new ContextProgressView(context, 1);
            this.progressView = contextProgressView;
            this.progressItem.addView(contextProgressView, LayoutHelper.createFrame(-1, -1.0f));
            this.progressView.setAlpha(0.0f);
            this.progressView.setScaleX(0.1f);
            this.progressView.setScaleY(0.1f);
            this.progressView.setVisibility(4);
        } else if (i == 1) {
            this.actionBar.setBackgroundColor(Theme.getColor(Theme.key_player_actionBar));
            this.actionBar.setItemsColor(Theme.getColor(Theme.key_player_actionBarItems), false);
            this.actionBar.setItemsBackgroundColor(Theme.getColor(Theme.key_player_actionBarSelector), false);
            this.actionBar.setTitleColor(Theme.getColor(Theme.key_player_actionBarTitle));
            this.actionBar.setSubtitleColor(Theme.getColor(Theme.key_player_actionBarSubtitle));
            this.actionBar.setTitle(LocaleController.getString("Statistics", R.string.Statistics));
            ContextProgressView contextProgressView2 = new ContextProgressView(context, 3);
            this.progressView = contextProgressView2;
            this.progressItem.addView(contextProgressView2, LayoutHelper.createFrame(-1, -1.0f));
            this.progressView.setAlpha(1.0f);
            this.progressView.setScaleX(1.0f);
            this.progressView.setScaleY(1.0f);
            this.progressView.setVisibility(0);
            this.progressItem.getContentView().setVisibility(8);
            this.progressItem.setEnabled(false);
        } else {
            if (this.mTitle != null) {
                this.actionBar.setTitle(this.mTitle);
            }
            ContextProgressView contextProgressView3 = new ContextProgressView(context, 3);
            this.progressView = contextProgressView3;
            this.progressItem.addView(contextProgressView3, LayoutHelper.createFrame(-1, -1.0f));
            this.progressView.setAlpha(1.0f);
            this.progressView.setScaleX(1.0f);
            this.progressView.setScaleY(1.0f);
            this.progressView.setVisibility(0);
            this.progressItem.getContentView().setVisibility(8);
            this.progressItem.setEnabled(false);
        }
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
            if (this.type == 0) {
                this.webView.addJavascriptInterface(new WebviewProxy(), "WebviewProxy");
            }
        }
        this.webView.setWebViewClient(new WebViewClient() { // from class: im.uwrkaxlmjj.ui.WebviewActivity.3
            private boolean isInternalUrl(String url) {
                if (TextUtils.isEmpty(url)) {
                    return false;
                }
                Uri uri = Uri.parse(url);
                if (!"".equals(uri.getScheme())) {
                    return false;
                }
                if (WebviewActivity.this.type == 1) {
                    try {
                        WebviewActivity.this.reloadStats(Uri.parse(url.replace("hchat:statsrefresh", "hchat://m12345.com")).getQueryParameter("params"));
                    } catch (Throwable e) {
                        FileLog.e(e);
                    }
                } else {
                    WebviewActivity.this.finishFragment(false);
                    try {
                        Intent intent = new Intent("android.intent.action.VIEW", uri);
                        ComponentName componentName = new ComponentName(ApplicationLoader.applicationContext.getPackageName(), LaunchActivity.class.getName());
                        intent.setComponent(componentName);
                        intent.putExtra("com.android.browser.application_id", ApplicationLoader.applicationContext.getPackageName());
                        ApplicationLoader.applicationContext.startActivity(intent);
                    } catch (Exception e2) {
                        FileLog.e(e2);
                    }
                }
                return true;
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
                    WebviewActivity.this.webView.loadUrl(url);
                }
                return super.shouldOverrideUrlLoading(view, url);
            }

            @Override // android.webkit.WebViewClient
            public void onPageFinished(WebView view, String url) {
                super.onPageFinished(view, url);
                if (WebviewActivity.this.progressView != null && WebviewActivity.this.progressView.getVisibility() == 0) {
                    AnimatorSet animatorSet = new AnimatorSet();
                    if (WebviewActivity.this.type == 0) {
                        WebviewActivity.this.progressItem.getContentView().setVisibility(0);
                        WebviewActivity.this.progressItem.setEnabled(true);
                        animatorSet.playTogether(ObjectAnimator.ofFloat(WebviewActivity.this.progressView, "scaleX", 1.0f, 0.1f), ObjectAnimator.ofFloat(WebviewActivity.this.progressView, "scaleY", 1.0f, 0.1f), ObjectAnimator.ofFloat(WebviewActivity.this.progressView, "alpha", 1.0f, 0.0f), ObjectAnimator.ofFloat(WebviewActivity.this.progressItem.getContentView(), "scaleX", 0.0f, 1.0f), ObjectAnimator.ofFloat(WebviewActivity.this.progressItem.getContentView(), "scaleY", 0.0f, 1.0f), ObjectAnimator.ofFloat(WebviewActivity.this.progressItem.getContentView(), "alpha", 0.0f, 1.0f));
                    } else {
                        animatorSet.playTogether(ObjectAnimator.ofFloat(WebviewActivity.this.progressView, "scaleX", 1.0f, 0.1f), ObjectAnimator.ofFloat(WebviewActivity.this.progressView, "scaleY", 1.0f, 0.1f), ObjectAnimator.ofFloat(WebviewActivity.this.progressView, "alpha", 1.0f, 0.0f));
                    }
                    animatorSet.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.WebviewActivity.3.1
                        @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                        public void onAnimationEnd(Animator animator) {
                            if (WebviewActivity.this.type == 1) {
                                WebviewActivity.this.progressItem.setVisibility(8);
                            } else {
                                WebviewActivity.this.progressView.setVisibility(4);
                            }
                        }
                    });
                    animatorSet.setDuration(150L);
                    animatorSet.start();
                }
            }
        });
        this.webView.setWebChromeClient(new WebChromeClient() { // from class: im.uwrkaxlmjj.ui.WebviewActivity.4
            @Override // android.webkit.WebChromeClient
            public void onReceivedTitle(WebView view, String title) {
                super.onReceivedTitle(view, title);
                if (WebviewActivity.this.mTitle == null && WebviewActivity.this.actionBar != null) {
                    WebviewActivity.this.actionBar.setTitle(title);
                }
            }
        });
        frameLayout.addView(this.webView, LayoutHelper.createFrame(-1, -1.0f));
        return this.fragmentView;
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
        AndroidUtilities.cancelRunOnUIThread(this.typingRunnable);
        this.typingRunnable.run();
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
    protected void onTransitionAnimationEnd(boolean isOpen, boolean backward) {
        WebView webView;
        if (isOpen && !backward && (webView = this.webView) != null) {
            webView.loadUrl(this.currentUrl);
        }
    }

    public static boolean supportWebview() {
        String manufacturer = Build.MANUFACTURER;
        String model = Build.MODEL;
        if ("samsung".equals(manufacturer) && "GT-I9500".equals(model)) {
            return false;
        }
        return true;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void reloadStats(String params) {
        if (this.loadStats) {
            return;
        }
        this.loadStats = true;
        TLRPC.TL_messages_getStatsURL req = new TLRPC.TL_messages_getStatsURL();
        req.peer = MessagesController.getInstance(this.currentAccount).getInputPeer((int) this.currentDialogId);
        req.params = params != null ? params : "";
        req.dark = Theme.getCurrentTheme().isDark();
        ConnectionsManager.getInstance(this.currentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$WebviewActivity$JdbvvXIgACB7oK0BqJ3m_V37OoE
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$reloadStats$1$WebviewActivity(tLObject, tL_error);
            }
        });
    }

    public /* synthetic */ void lambda$reloadStats$1$WebviewActivity(final TLObject response, TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$WebviewActivity$zfGX5q-21cLbdNYh8XJSiIo-yeo
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$0$WebviewActivity(response);
            }
        });
    }

    public /* synthetic */ void lambda$null$0$WebviewActivity(TLObject response) {
        this.loadStats = false;
        if (response != null) {
            TLRPC.TL_statsURL url = (TLRPC.TL_statsURL) response;
            WebView webView = this.webView;
            String str = url.url;
            this.currentUrl = str;
            webView.loadUrl(str);
        }
    }

    public static void openGameInBrowser(String urlStr, MessageObject messageObject, Activity parentActivity, String short_name, String username) {
        String url;
        SerializedData serializedData;
        String string = "";
        try {
            SharedPreferences sharedPreferences = ApplicationLoader.applicationContext.getSharedPreferences("botshare", 0);
            String existing = sharedPreferences.getString("" + messageObject.getId(), null);
            StringBuilder hash = new StringBuilder(existing != null ? existing : "");
            StringBuilder addHash = new StringBuilder("tgShareScoreUrl=" + URLEncoder.encode("hchat://share_game_score?hash=", "UTF-8"));
            if (existing == null) {
                char[] chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ".toCharArray();
                for (int i = 0; i < 20; i++) {
                    hash.append(chars[Utilities.random.nextInt(chars.length)]);
                }
            }
            addHash.append((CharSequence) hash);
            int index = urlStr.indexOf(35);
            if (index < 0) {
                url = urlStr + "#" + ((Object) addHash);
            } else {
                String curHash = urlStr.substring(index + 1);
                if (curHash.indexOf(61) >= 0 || curHash.indexOf(63) >= 0) {
                    url = urlStr + "&" + ((Object) addHash);
                } else if (curHash.length() > 0) {
                    url = urlStr + "?" + ((Object) addHash);
                } else {
                    url = urlStr + ((Object) addHash);
                }
            }
            SharedPreferences.Editor editor = sharedPreferences.edit();
            editor.putInt(((Object) hash) + "_date", (int) (System.currentTimeMillis() / 1000));
            serializedData = new SerializedData(messageObject.messageOwner.getObjectSize());
            messageObject.messageOwner.serializeToStream(serializedData);
            editor.putString(((Object) hash) + "_m", Utilities.bytesToHex(serializedData.toByteArray()));
            String str = ((Object) hash) + "_link";
            StringBuilder sb = new StringBuilder();
            sb.append(DefaultWebClient.HTTPS_SCHEME);
            sb.append(MessagesController.getInstance(messageObject.currentAccount).linkPrefix);
            sb.append("/");
            try {
                sb.append(username);
                if (!TextUtils.isEmpty(short_name)) {
                    StringBuilder sb2 = new StringBuilder();
                    sb2.append("?game=");
                    try {
                        sb2.append(short_name);
                        string = sb2.toString();
                    } catch (Exception e) {
                        e = e;
                        FileLog.e(e);
                    }
                }
                sb.append(string);
                editor.putString(str, sb.toString());
                editor.commit();
            } catch (Exception e2) {
                e = e2;
            }
        } catch (Exception e3) {
            e = e3;
        }
        try {
            Browser.openUrl((Context) parentActivity, url, false);
            serializedData.cleanup();
        } catch (Exception e4) {
            e = e4;
            FileLog.e(e);
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public ThemeDescription[] getThemeDescriptions() {
        if (this.type == 0) {
            return new ThemeDescription[]{new ThemeDescription(this.fragmentView, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_windowBackgroundWhite), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_actionBarDefault), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_ITEMSCOLOR, null, null, null, null, Theme.key_actionBarDefaultIcon), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_TITLECOLOR, null, null, null, null, Theme.key_actionBarDefaultTitle), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_SELECTORCOLOR, null, null, null, null, Theme.key_actionBarDefaultSelector), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_SUBMENUBACKGROUND, null, null, null, null, Theme.key_actionBarDefaultSubmenuBackground), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_SUBMENUITEM, null, null, null, null, Theme.key_actionBarDefaultSubmenuItem), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_SUBMENUITEM | ThemeDescription.FLAG_IMAGECOLOR, null, null, null, null, Theme.key_actionBarDefaultSubmenuItemIcon), new ThemeDescription(this.progressView, 0, null, null, null, null, Theme.key_contextProgressInner2), new ThemeDescription(this.progressView, 0, null, null, null, null, Theme.key_contextProgressOuter2)};
        }
        return new ThemeDescription[]{new ThemeDescription(this.fragmentView, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_windowBackgroundWhite), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_player_actionBar), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_ITEMSCOLOR, null, null, null, null, Theme.key_player_actionBarItems), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_TITLECOLOR, null, null, null, null, Theme.key_player_actionBarTitle), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_SUBTITLECOLOR, null, null, null, null, Theme.key_player_actionBarTitle), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_SELECTORCOLOR, null, null, null, null, Theme.key_player_actionBarSelector), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_SUBMENUBACKGROUND, null, null, null, null, Theme.key_actionBarDefaultSubmenuBackground), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_SUBMENUITEM, null, null, null, null, Theme.key_actionBarDefaultSubmenuItem), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_SUBMENUITEM | ThemeDescription.FLAG_IMAGECOLOR, null, null, null, null, Theme.key_actionBarDefaultSubmenuItemIcon), new ThemeDescription(this.progressView, 0, null, null, null, null, Theme.key_contextProgressInner4), new ThemeDescription(this.progressView, 0, null, null, null, null, Theme.key_contextProgressOuter4)};
    }
}
