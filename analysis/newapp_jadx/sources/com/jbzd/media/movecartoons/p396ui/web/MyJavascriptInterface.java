package com.jbzd.media.movecartoons.p396ui.web;

import android.app.Activity;
import android.content.SharedPreferences;
import android.webkit.JavascriptInterface;
import android.webkit.WebView;
import androidx.core.app.NotificationCompat;
import com.gyf.immersionbar.ImmersionBar;
import com.jbzd.media.movecartoons.MyApp;
import com.jbzd.media.movecartoons.bean.TokenBean;
import com.jbzd.media.movecartoons.p396ui.chat.ChatDetailActivity;
import com.jbzd.media.movecartoons.p396ui.share.InviteActivity;
import com.jbzd.media.movecartoons.p396ui.share.ShareListActivity;
import com.jbzd.media.movecartoons.p396ui.vip.BuyActivity;
import com.jbzd.media.movecartoons.p396ui.wallet.RechargeActivity;
import com.jbzd.media.movecartoons.p396ui.web.MyJavascriptInterface;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import p005b.p006a.p007a.p008a.p009a.C0840d;
import p005b.p327w.p330b.C2827a;
import p005b.p327w.p330b.p331b.ApplicationC2828a;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000.\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0004\n\u0002\u0010\b\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0007\u0018\u00002\u00020\u0001B\u0017\u0012\u0006\u0010\u0015\u001a\u00020\u0014\u0012\u0006\u0010\u0010\u001a\u00020\u000f¢\u0006\u0004\b\u0019\u0010\u001aJ\u0017\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0003\u001a\u00020\u0002H\u0007¢\u0006\u0004\b\u0005\u0010\u0006J\u0017\u0010\b\u001a\u00020\u00042\u0006\u0010\u0007\u001a\u00020\u0002H\u0007¢\u0006\u0004\b\b\u0010\u0006J\u000f\u0010\n\u001a\u00020\tH\u0007¢\u0006\u0004\b\n\u0010\u000bJ\u000f\u0010\f\u001a\u00020\u0002H\u0007¢\u0006\u0004\b\f\u0010\rJ\u000f\u0010\u000e\u001a\u00020\u0002H\u0007¢\u0006\u0004\b\u000e\u0010\rR\u0019\u0010\u0010\u001a\u00020\u000f8\u0006@\u0006¢\u0006\f\n\u0004\b\u0010\u0010\u0011\u001a\u0004\b\u0012\u0010\u0013R\u0019\u0010\u0015\u001a\u00020\u00148\u0006@\u0006¢\u0006\f\n\u0004\b\u0015\u0010\u0016\u001a\u0004\b\u0017\u0010\u0018¨\u0006\u001b"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/web/MyJavascriptInterface;", "", "", "key", "", "jumpIntent", "(Ljava/lang/String;)V", "link", "jumpAd", "", "getBarHeight", "()I", "getUserCode", "()Ljava/lang/String;", "getTheme", "Landroid/webkit/WebView;", "webView", "Landroid/webkit/WebView;", "getWebView", "()Landroid/webkit/WebView;", "Landroid/app/Activity;", "context", "Landroid/app/Activity;", "getContext", "()Landroid/app/Activity;", "<init>", "(Landroid/app/Activity;Landroid/webkit/WebView;)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class MyJavascriptInterface {

    @NotNull
    private final Activity context;

    @NotNull
    private final WebView webView;

    public MyJavascriptInterface(@NotNull Activity context, @NotNull WebView webView) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(webView, "webView");
        this.context = context;
        this.webView = webView;
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: jumpIntent$lambda-0, reason: not valid java name */
    public static final void m6020jumpIntent$lambda0(MyJavascriptInterface this$0) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        if (this$0.getWebView().canGoBack()) {
            this$0.getWebView().goBack();
        } else {
            this$0.getContext().onBackPressed();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: jumpIntent$lambda-1, reason: not valid java name */
    public static final void m6021jumpIntent$lambda1(MyJavascriptInterface this$0) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        this$0.getContext().onBackPressed();
    }

    @JavascriptInterface
    public final int getBarHeight() {
        return ImmersionBar.getStatusBarHeight(this.context);
    }

    @NotNull
    public final Activity getContext() {
        return this.context;
    }

    @JavascriptInterface
    @NotNull
    public final String getTheme() {
        Intrinsics.checkNotNullParameter("MY_THEME_KEY", "key");
        ApplicationC2828a applicationC2828a = C2827a.f7670a;
        if (applicationC2828a == null) {
            Intrinsics.throwUninitializedPropertyAccessException("context");
            throw null;
        }
        SharedPreferences sharedPreferences = applicationC2828a.getSharedPreferences("default_storage", 0);
        Intrinsics.checkNotNullExpressionValue(sharedPreferences, "SupportLibraryInstance.context.getSharedPreferences(DEFAULT_STORAGE_NAME,Context.MODE_PRIVATE)");
        return sharedPreferences.getBoolean("MY_THEME_KEY", false) ? "1" : "0";
    }

    @JavascriptInterface
    @NotNull
    public final String getUserCode() {
        String str;
        MyApp myApp = MyApp.f9891f;
        TokenBean m4186g = MyApp.m4186g();
        return (m4186g == null || (str = m4186g.username) == null) ? "" : str;
    }

    @NotNull
    public final WebView getWebView() {
        return this.webView;
    }

    @JavascriptInterface
    public final void jumpAd(@NotNull String link) {
        Intrinsics.checkNotNullParameter(link, "link");
        C0840d.a.m174d(C0840d.f235a, this.context, link, null, null, 12);
    }

    /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue
    java.lang.NullPointerException: Cannot invoke "java.util.List.iterator()" because the return value of "jadx.core.dex.visitors.regions.SwitchOverStringVisitor$SwitchData.getNewCases()" is null
    	at jadx.core.dex.visitors.regions.SwitchOverStringVisitor.restoreSwitchOverString(SwitchOverStringVisitor.java:109)
    	at jadx.core.dex.visitors.regions.SwitchOverStringVisitor.visitRegion(SwitchOverStringVisitor.java:66)
    	at jadx.core.dex.visitors.regions.DepthRegionTraversal.traverseIterativeStepInternal(DepthRegionTraversal.java:77)
    	at jadx.core.dex.visitors.regions.DepthRegionTraversal.traverseIterativeStepInternal(DepthRegionTraversal.java:82)
    	at jadx.core.dex.visitors.regions.DepthRegionTraversal.traverseIterative(DepthRegionTraversal.java:31)
    	at jadx.core.dex.visitors.regions.SwitchOverStringVisitor.visit(SwitchOverStringVisitor.java:60)
     */
    @JavascriptInterface
    public final void jumpIntent(@NotNull String key) {
        Intrinsics.checkNotNullParameter(key, "key");
        switch (key.hashCode()) {
            case -1274442605:
                if (key.equals("finish")) {
                    this.context.runOnUiThread(new Runnable() { // from class: b.a.a.a.t.s.a
                        @Override // java.lang.Runnable
                        public final void run() {
                            MyJavascriptInterface.m6021jumpIntent$lambda1(MyJavascriptInterface.this);
                        }
                    });
                    break;
                }
                break;
            case -182170699:
                if (key.equals("myinvite")) {
                    ShareListActivity.INSTANCE.start(this.context);
                    break;
                }
                break;
            case 3015911:
                if (key.equals("back")) {
                    this.context.runOnUiThread(new Runnable() { // from class: b.a.a.a.t.s.b
                        @Override // java.lang.Runnable
                        public final void run() {
                            MyJavascriptInterface.m6020jumpIntent$lambda0(MyJavascriptInterface.this);
                        }
                    });
                    break;
                }
                break;
            case 109400031:
                if (key.equals("share")) {
                    InviteActivity.INSTANCE.start(this.context);
                    break;
                }
                break;
            case 883661939:
                if (key.equals("chargeDiamonds")) {
                    RechargeActivity.INSTANCE.start(this.context);
                    break;
                }
                break;
            case 1569767625:
                if (key.equals("chargeVip")) {
                    BuyActivity.INSTANCE.start(this.context);
                    break;
                }
                break;
            case 1984153269:
                if (key.equals(NotificationCompat.CATEGORY_SERVICE)) {
                    ChatDetailActivity.Companion.start$default(ChatDetailActivity.INSTANCE, this.context, null, null, null, null, 30, null);
                    break;
                }
                break;
        }
    }
}
