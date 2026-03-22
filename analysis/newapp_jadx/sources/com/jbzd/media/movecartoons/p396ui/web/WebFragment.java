package com.jbzd.media.movecartoons.p396ui.web;

import android.os.Bundle;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewParent;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.widget.FrameLayout;
import androidx.fragment.app.FragmentActivity;
import com.jbzd.media.movecartoons.MyApp;
import com.qnmd.adnnm.da0yzo.R;
import com.qunidayede.supportlibrary.core.view.BaseFragment;
import java.util.Objects;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt__StringsKt;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000@\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0010\b\n\u0002\b\u0004\n\u0002\u0010\u000b\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0010\u000e\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0007\u0018\u0000 &2\u00020\u0001:\u0001&B\u0007¢\u0006\u0004\b%\u0010\u0004J\u000f\u0010\u0003\u001a\u00020\u0002H\u0002¢\u0006\u0004\b\u0003\u0010\u0004J\u0019\u0010\u0007\u001a\u00020\u00022\b\u0010\u0006\u001a\u0004\u0018\u00010\u0005H\u0002¢\u0006\u0004\b\u0007\u0010\bJ\u000f\u0010\t\u001a\u00020\u0002H\u0002¢\u0006\u0004\b\t\u0010\u0004J\u000f\u0010\u000b\u001a\u00020\nH\u0016¢\u0006\u0004\b\u000b\u0010\fJ\u000f\u0010\r\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\r\u0010\u0004J\u000f\u0010\u000e\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\u000e\u0010\u0004J\r\u0010\u0010\u001a\u00020\u000f¢\u0006\u0004\b\u0010\u0010\u0011R\u001d\u0010\u0006\u001a\u00020\u00058F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u0012\u0010\u0013\u001a\u0004\b\u0014\u0010\u0015R\u001d\u0010\u001a\u001a\u00020\u00168F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u0017\u0010\u0013\u001a\u0004\b\u0018\u0010\u0019R\u001d\u0010\u001f\u001a\u00020\u001b8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u001c\u0010\u0013\u001a\u0004\b\u001d\u0010\u001eR\u001d\u0010$\u001a\u00020 8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b!\u0010\u0013\u001a\u0004\b\"\u0010#¨\u0006'"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/web/WebFragment;", "Lcom/qunidayede/supportlibrary/core/view/BaseFragment;", "", "initWebView", "()V", "Landroid/webkit/WebView;", "webView", "fullReleaseWebView", "(Landroid/webkit/WebView;)V", "releaseResources", "", "getLayout", "()I", "initEvents", "onPause", "", "goBackAct", "()Z", "webView$delegate", "Lkotlin/Lazy;", "getWebView", "()Landroid/webkit/WebView;", "Landroid/webkit/WebSettings;", "webSettings$delegate", "getWebSettings", "()Landroid/webkit/WebSettings;", "webSettings", "", "url$delegate", "getUrl", "()Ljava/lang/String;", "url", "Landroid/widget/FrameLayout;", "web_container$delegate", "getWeb_container", "()Landroid/widget/FrameLayout;", "web_container", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class WebFragment extends BaseFragment {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    /* renamed from: url$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy url = LazyKt__LazyJVMKt.lazy(new Function0<String>() { // from class: com.jbzd.media.movecartoons.ui.web.WebFragment$url$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final String invoke() {
            String string = WebFragment.this.requireArguments().getString("KEY_URL");
            return string == null ? "" : string;
        }
    });

    /* renamed from: webView$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy webView = LazyKt__LazyJVMKt.lazy(new Function0<WebView>() { // from class: com.jbzd.media.movecartoons.ui.web.WebFragment$webView$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final WebView invoke() {
            MyApp myApp = MyApp.f9891f;
            return new WebView(MyApp.m4183d());
        }
    });

    /* renamed from: webSettings$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy webSettings = LazyKt__LazyJVMKt.lazy(new Function0<WebSettings>() { // from class: com.jbzd.media.movecartoons.ui.web.WebFragment$webSettings$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final WebSettings invoke() {
            return WebFragment.this.getWebView().getSettings();
        }
    });

    /* renamed from: web_container$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy web_container = LazyKt__LazyJVMKt.lazy(new Function0<FrameLayout>() { // from class: com.jbzd.media.movecartoons.ui.web.WebFragment$web_container$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final FrameLayout invoke() {
            View view = WebFragment.this.getView();
            FrameLayout frameLayout = view == null ? null : (FrameLayout) view.findViewById(R.id.web_container);
            Intrinsics.checkNotNull(frameLayout);
            return frameLayout;
        }
    });

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0016\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0005\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0007\u0010\bJ\u0017\u0010\u0005\u001a\u00020\u00042\b\u0010\u0003\u001a\u0004\u0018\u00010\u0002¢\u0006\u0004\b\u0005\u0010\u0006¨\u0006\t"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/web/WebFragment$Companion;", "", "", "url", "Lcom/jbzd/media/movecartoons/ui/web/WebFragment;", "newInstance", "(Ljava/lang/String;)Lcom/jbzd/media/movecartoons/ui/web/WebFragment;", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        @NotNull
        public final WebFragment newInstance(@Nullable String url) {
            WebFragment webFragment = new WebFragment();
            Bundle bundle = new Bundle();
            bundle.putString("KEY_URL", url);
            Unit unit = Unit.INSTANCE;
            webFragment.setArguments(bundle);
            return webFragment;
        }
    }

    private final void fullReleaseWebView(WebView webView) {
        if (webView == null || webView.getParent() == null) {
            return;
        }
        ViewParent parent = webView.getParent();
        Objects.requireNonNull(parent, "null cannot be cast to non-null type android.view.ViewGroup");
        ((ViewGroup) parent).removeView(webView);
        webView.stopLoading();
        webView.getSettings().setJavaScriptEnabled(false);
        webView.clearHistory();
        webView.clearView();
        webView.removeAllViews();
        webView.destroy();
    }

    private final String getUrl() {
        return (String) this.url.getValue();
    }

    private final void initWebView() {
        getWebSettings().setJavaScriptEnabled(true);
        getWebSettings().setDomStorageEnabled(true);
        getWebSettings().setAppCacheMaxSize(8388608L);
        FragmentActivity activity = getActivity();
        if (activity != null) {
            getWebSettings().setAppCachePath(activity.getApplicationContext().getCacheDir().getAbsolutePath());
        }
        getWebSettings().setAllowFileAccess(true);
        getWebSettings().setAppCacheEnabled(true);
    }

    private final void releaseResources() {
        fullReleaseWebView(getWebView());
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseFragment
    public void _$_clearFindViewByIdCache() {
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseFragment
    public int getLayout() {
        return R.layout.web_act;
    }

    @NotNull
    public final WebSettings getWebSettings() {
        return (WebSettings) this.webSettings.getValue();
    }

    @NotNull
    public final WebView getWebView() {
        return (WebView) this.webView.getValue();
    }

    @NotNull
    public final FrameLayout getWeb_container() {
        return (FrameLayout) this.web_container.getValue();
    }

    public final boolean goBackAct() {
        if (!getWebView().canGoBack()) {
            return true;
        }
        getWebView().goBack();
        return false;
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseFragment
    public void initEvents() {
        String url;
        String str;
        getWeb_container().addView(getWebView(), 0, new ViewGroup.LayoutParams(-1, -1));
        initWebView();
        FragmentActivity activity = getActivity();
        if (activity != null) {
            getWebView().addJavascriptInterface(new MyJavascriptInterface(activity, getWebView()), "androidWP");
        }
        WebView webView = getWebView();
        String url2 = getUrl();
        Intrinsics.checkNotNullExpressionValue(url2, "url");
        if (StringsKt__StringsKt.contains$default((CharSequence) url2, '?', false, 2, (Object) null)) {
            url = getUrl();
            str = "&navBarHeight=25";
        } else {
            url = getUrl();
            str = "?navBarHeight=25";
        }
        webView.loadUrl(Intrinsics.stringPlus(url, str));
    }

    @Override // androidx.fragment.app.Fragment
    public void onPause() {
        super.onPause();
        FragmentActivity activity = getActivity();
        if (activity != null && activity.isFinishing()) {
            releaseResources();
        }
    }
}
