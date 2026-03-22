package com.jbzd.media.movecartoons.p396ui.download;

import android.content.Context;
import android.content.Intent;
import android.content.res.Configuration;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewParent;
import android.webkit.WebChromeClient;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.widget.FrameLayout;
import android.widget.ImageButton;
import com.gyf.immersionbar.ImmersionBar;
import com.jbzd.media.movecartoons.MyApp;
import com.jbzd.media.movecartoons.R$id;
import com.jbzd.media.movecartoons.p396ui.download.WebPlayerActivity;
import com.jbzd.media.movecartoons.p396ui.web.MyJavascriptInterface;
import com.qnmd.adnnm.da0yzo.R;
import com.qunidayede.supportlibrary.core.view.BaseActivity;
import java.lang.reflect.Method;
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

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000@\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\b\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0010\u000e\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u000b\u0018\u0000 (2\u00020\u0001:\u0002()B\u0007¢\u0006\u0004\b'\u0010\u0004J\u000f\u0010\u0003\u001a\u00020\u0002H\u0002¢\u0006\u0004\b\u0003\u0010\u0004J\u0019\u0010\u0007\u001a\u00020\u00022\b\u0010\u0006\u001a\u0004\u0018\u00010\u0005H\u0002¢\u0006\u0004\b\u0007\u0010\bJ\u000f\u0010\n\u001a\u00020\tH\u0016¢\u0006\u0004\b\n\u0010\u000bJ\u000f\u0010\f\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\f\u0010\u0004J\u000f\u0010\r\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\r\u0010\u0004J\u0017\u0010\u0010\u001a\u00020\u00022\u0006\u0010\u000f\u001a\u00020\u000eH\u0016¢\u0006\u0004\b\u0010\u0010\u0011J\u000f\u0010\u0012\u001a\u00020\u0002H\u0014¢\u0006\u0004\b\u0012\u0010\u0004J\u000f\u0010\u0013\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\u0013\u0010\u0004R\u001f\u0010\u0019\u001a\u0004\u0018\u00010\u00148B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u0015\u0010\u0016\u001a\u0004\b\u0017\u0010\u0018R!\u0010\u001e\u001a\u00060\u001aR\u00020\u00008F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u001b\u0010\u0016\u001a\u0004\b\u001c\u0010\u001dR\u001d\u0010#\u001a\u00020\u001f8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b \u0010\u0016\u001a\u0004\b!\u0010\"R\u001d\u0010\u0006\u001a\u00020\u00058F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b$\u0010\u0016\u001a\u0004\b%\u0010&¨\u0006*"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/download/WebPlayerActivity;", "Lcom/qunidayede/supportlibrary/core/view/BaseActivity;", "", "initWebView", "()V", "Landroid/webkit/WebView;", "webView", "fullReleaseWebView", "(Landroid/webkit/WebView;)V", "", "getLayoutId", "()I", "initStatusBar", "bindEvent", "Landroid/content/res/Configuration;", "newConfig", "onConfigurationChanged", "(Landroid/content/res/Configuration;)V", "onPause", "releaseResources", "", "url$delegate", "Lkotlin/Lazy;", "getUrl", "()Ljava/lang/String;", "url", "Lcom/jbzd/media/movecartoons/ui/download/WebPlayerActivity$MyWebChromeClient;", "myChromeClient$delegate", "getMyChromeClient", "()Lcom/jbzd/media/movecartoons/ui/download/WebPlayerActivity$MyWebChromeClient;", "myChromeClient", "Landroid/webkit/WebSettings;", "webSettings$delegate", "getWebSettings", "()Landroid/webkit/WebSettings;", "webSettings", "webView$delegate", "getWebView", "()Landroid/webkit/WebView;", "<init>", "Companion", "MyWebChromeClient", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class WebPlayerActivity extends BaseActivity {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    /* renamed from: url$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy url = LazyKt__LazyJVMKt.lazy(new Function0<String>() { // from class: com.jbzd.media.movecartoons.ui.download.WebPlayerActivity$url$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @Nullable
        public final String invoke() {
            return WebPlayerActivity.this.getIntent().getStringExtra("KEY_URL");
        }
    });

    /* renamed from: myChromeClient$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy myChromeClient = LazyKt__LazyJVMKt.lazy(new Function0<MyWebChromeClient>() { // from class: com.jbzd.media.movecartoons.ui.download.WebPlayerActivity$myChromeClient$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final WebPlayerActivity.MyWebChromeClient invoke() {
            return new WebPlayerActivity.MyWebChromeClient(WebPlayerActivity.this);
        }
    });

    /* renamed from: webView$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy webView = LazyKt__LazyJVMKt.lazy(new Function0<WebView>() { // from class: com.jbzd.media.movecartoons.ui.download.WebPlayerActivity$webView$2
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
    private final Lazy webSettings = LazyKt__LazyJVMKt.lazy(new Function0<WebSettings>() { // from class: com.jbzd.media.movecartoons.ui.download.WebPlayerActivity$webSettings$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final WebSettings invoke() {
            return WebPlayerActivity.this.getWebView().getSettings();
        }
    });

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u001c\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0005\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\t\u0010\nJ\u001d\u0010\u0007\u001a\u00020\u00062\u0006\u0010\u0003\u001a\u00020\u00022\u0006\u0010\u0005\u001a\u00020\u0004¢\u0006\u0004\b\u0007\u0010\b¨\u0006\u000b"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/download/WebPlayerActivity$Companion;", "", "Landroid/content/Context;", "context", "", "url", "", "start", "(Landroid/content/Context;Ljava/lang/String;)V", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public final void start(@NotNull Context context, @NotNull String url) {
            Intrinsics.checkNotNullParameter(context, "context");
            Intrinsics.checkNotNullParameter(url, "url");
            Intent intent = new Intent(context, (Class<?>) WebPlayerActivity.class);
            intent.putExtra("KEY_URL", url);
            Unit unit = Unit.INSTANCE;
            context.startActivity(intent);
        }
    }

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000&\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0010\u000b\n\u0002\b\u000e\b\u0086\u0004\u0018\u00002\u00020\u0001B\u0007¢\u0006\u0004\b\u0018\u0010\u0019J\u000f\u0010\u0003\u001a\u00020\u0002H\u0002¢\u0006\u0004\b\u0003\u0010\u0004J#\u0010\t\u001a\u00020\u00022\b\u0010\u0006\u001a\u0004\u0018\u00010\u00052\b\u0010\b\u001a\u0004\u0018\u00010\u0007H\u0016¢\u0006\u0004\b\t\u0010\nJ\u000f\u0010\u000b\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\u000b\u0010\u0004R\"\u0010\r\u001a\u00020\f8\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\r\u0010\u000e\u001a\u0004\b\r\u0010\u000f\"\u0004\b\u0010\u0010\u0011R$\u0010\u0012\u001a\u0004\u0018\u00010\u00078\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\u0012\u0010\u0013\u001a\u0004\b\u0014\u0010\u0015\"\u0004\b\u0016\u0010\u0017¨\u0006\u001a"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/download/WebPlayerActivity$MyWebChromeClient;", "Landroid/webkit/WebChromeClient;", "", "fullScreen", "()V", "Landroid/view/View;", "view", "Landroid/webkit/WebChromeClient$CustomViewCallback;", "callback", "onShowCustomView", "(Landroid/view/View;Landroid/webkit/WebChromeClient$CustomViewCallback;)V", "onHideCustomView", "", "isFullScreen", "Z", "()Z", "setFullScreen", "(Z)V", "mCallback", "Landroid/webkit/WebChromeClient$CustomViewCallback;", "getMCallback", "()Landroid/webkit/WebChromeClient$CustomViewCallback;", "setMCallback", "(Landroid/webkit/WebChromeClient$CustomViewCallback;)V", "<init>", "(Lcom/jbzd/media/movecartoons/ui/download/WebPlayerActivity;)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public final class MyWebChromeClient extends WebChromeClient {
        private boolean isFullScreen;

        @Nullable
        private WebChromeClient.CustomViewCallback mCallback;
        public final /* synthetic */ WebPlayerActivity this$0;

        public MyWebChromeClient(WebPlayerActivity this$0) {
            Intrinsics.checkNotNullParameter(this$0, "this$0");
            this.this$0 = this$0;
        }

        private final void fullScreen() {
            if (this.this$0.getResources().getConfiguration().orientation == 1) {
                this.this$0.setRequestedOrientation(0);
                this.isFullScreen = true;
            } else {
                this.this$0.setRequestedOrientation(1);
                this.isFullScreen = false;
            }
        }

        @Nullable
        public final WebChromeClient.CustomViewCallback getMCallback() {
            return this.mCallback;
        }

        /* renamed from: isFullScreen, reason: from getter */
        public final boolean getIsFullScreen() {
            return this.isFullScreen;
        }

        @Override // android.webkit.WebChromeClient
        public void onHideCustomView() {
            ((ImageButton) this.this$0.findViewById(R$id.btn_back)).setVisibility(0);
            fullScreen();
            this.this$0.getWebView().setVisibility(0);
            WebPlayerActivity webPlayerActivity = this.this$0;
            int i2 = R$id.flVideoContainer;
            ((FrameLayout) webPlayerActivity.findViewById(i2)).setVisibility(8);
            ((FrameLayout) this.this$0.findViewById(i2)).removeAllViews();
            super.onHideCustomView();
        }

        @Override // android.webkit.WebChromeClient
        public void onShowCustomView(@Nullable View view, @Nullable WebChromeClient.CustomViewCallback callback) {
            ((ImageButton) this.this$0.findViewById(R$id.btn_back)).setVisibility(8);
            fullScreen();
            this.this$0.getWebView().setVisibility(8);
            WebPlayerActivity webPlayerActivity = this.this$0;
            int i2 = R$id.flVideoContainer;
            ((FrameLayout) webPlayerActivity.findViewById(i2)).setVisibility(0);
            ((FrameLayout) this.this$0.findViewById(i2)).addView(view);
            this.mCallback = callback;
            super.onShowCustomView(view, callback);
        }

        public final void setFullScreen(boolean z) {
            this.isFullScreen = z;
        }

        public final void setMCallback(@Nullable WebChromeClient.CustomViewCallback customViewCallback) {
            this.mCallback = customViewCallback;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: bindEvent$lambda-0, reason: not valid java name */
    public static final void m5804bindEvent$lambda0(WebPlayerActivity this$0, View view) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        this$0.finish();
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
        getWebSettings().setUseWideViewPort(true);
        getWebSettings().setLoadWithOverviewMode(true);
        getWebSettings().setAllowFileAccess(true);
        getWebSettings().setJavaScriptCanOpenWindowsAutomatically(true);
        getWebSettings().setMediaPlaybackRequiresUserGesture(false);
        try {
            Method method = getWebSettings().getClass().getMethod("setAllowUniversalAccessFromFileURLs", Boolean.TYPE);
            if (method != null) {
                method.invoke(getWebSettings(), Boolean.TRUE);
            }
        } catch (Exception e2) {
            e2.printStackTrace();
        }
        getWebSettings().setMixedContentMode(0);
        getWebView().setWebChromeClient(getMyChromeClient());
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseActivity
    public void _$_clearFindViewByIdCache() {
    }

    @Override // p005b.p327w.p330b.p331b.p334e.InterfaceC2847j
    public void bindEvent() {
        String url;
        String str;
        ((ImageButton) findViewById(R$id.btn_back)).setOnClickListener(new View.OnClickListener() { // from class: b.a.a.a.t.f.f
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                WebPlayerActivity.m5804bindEvent$lambda0(WebPlayerActivity.this, view);
            }
        });
        getWebView().setBackgroundResource(R.color.bgBlack);
        getWebView().getBackground().setAlpha(0);
        ((FrameLayout) findViewById(R$id.web_container)).addView(getWebView(), 0, new ViewGroup.LayoutParams(-1, -1));
        initWebView();
        getWebView().addJavascriptInterface(new MyJavascriptInterface(this, getWebView()), "androidWP");
        WebView webView = getWebView();
        String url2 = getUrl();
        if (Intrinsics.areEqual(url2 != null ? Boolean.valueOf(StringsKt__StringsKt.contains$default((CharSequence) url2, '?', false, 2, (Object) null)) : null, Boolean.TRUE)) {
            url = getUrl();
            str = "&navBarHeight=25";
        } else {
            url = getUrl();
            str = "?navBarHeight=25";
        }
        webView.loadUrl(Intrinsics.stringPlus(url, str));
    }

    @Override // p005b.p327w.p330b.p331b.p334e.InterfaceC2847j
    public int getLayoutId() {
        return R.layout.web_play_act;
    }

    @NotNull
    public final MyWebChromeClient getMyChromeClient() {
        return (MyWebChromeClient) this.myChromeClient.getValue();
    }

    @NotNull
    public final WebSettings getWebSettings() {
        return (WebSettings) this.webSettings.getValue();
    }

    @NotNull
    public final WebView getWebView() {
        return (WebView) this.webView.getValue();
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseActivity
    public void initStatusBar() {
        ImmersionBar.with(this).fitsSystemWindows(false).navigationBarColor("#FFFFFF").statusBarDarkFont(true).init();
    }

    @Override // androidx.appcompat.app.AppCompatActivity, androidx.fragment.app.FragmentActivity, android.app.Activity, android.content.ComponentCallbacks
    public void onConfigurationChanged(@NotNull Configuration newConfig) {
        Intrinsics.checkNotNullParameter(newConfig, "newConfig");
        super.onConfigurationChanged(newConfig);
        int i2 = newConfig.orientation;
        if (i2 == 1) {
            getWindow().clearFlags(1024);
            getWindow().addFlags(2048);
        } else {
            if (i2 != 2) {
                return;
            }
            getWindow().clearFlags(2048);
            getWindow().addFlags(1024);
        }
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseActivity, androidx.fragment.app.FragmentActivity, android.app.Activity
    public void onPause() {
        super.onPause();
        if (isFinishing()) {
            releaseResources();
        }
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseActivity
    public void releaseResources() {
        fullReleaseWebView(getWebView());
    }
}
