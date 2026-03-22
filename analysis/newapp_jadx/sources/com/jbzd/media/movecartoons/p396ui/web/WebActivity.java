package com.jbzd.media.movecartoons.p396ui.web;

import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.view.ViewGroup;
import android.view.ViewParent;
import android.webkit.ValueCallback;
import android.webkit.WebChromeClient;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.widget.FrameLayout;
import androidx.activity.result.ActivityResult;
import androidx.activity.result.ActivityResultCallback;
import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import com.jbzd.media.movecartoons.MyApp;
import com.jbzd.media.movecartoons.p396ui.web.WebActivity;
import com.qnmd.adnnm.da0yzo.R;
import com.qunidayede.supportlibrary.core.view.BaseActivity;
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

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000T\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\b\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\u0010\u0011\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0007\n\u0002\u0010\u000e\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0007\u0018\u0000 22\u00020\u0001:\u00012B\u0007¢\u0006\u0004\b1\u0010\u0004J\u000f\u0010\u0003\u001a\u00020\u0002H\u0002¢\u0006\u0004\b\u0003\u0010\u0004J\u0019\u0010\u0007\u001a\u00020\u00022\b\u0010\u0006\u001a\u0004\u0018\u00010\u0005H\u0002¢\u0006\u0004\b\u0007\u0010\bJ\u000f\u0010\n\u001a\u00020\tH\u0016¢\u0006\u0004\b\n\u0010\u000bJ\u000f\u0010\f\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\f\u0010\u0004J\u000f\u0010\r\u001a\u00020\u0002H\u0014¢\u0006\u0004\b\r\u0010\u0004J\u000f\u0010\u000e\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\u000e\u0010\u0004J\u000f\u0010\u000f\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\u000f\u0010\u0004R0\u0010\u0013\u001a\u0010\u0012\n\u0012\b\u0012\u0004\u0012\u00020\u00120\u0011\u0018\u00010\u00108\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\u0013\u0010\u0014\u001a\u0004\b\u0015\u0010\u0016\"\u0004\b\u0017\u0010\u0018R$\u0010\u001c\u001a\u0010\u0012\f\u0012\n \u001b*\u0004\u0018\u00010\u001a0\u001a0\u00198\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\b\u001c\u0010\u001dR\u001d\u0010\u0006\u001a\u00020\u00058F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u001e\u0010\u001f\u001a\u0004\b \u0010!R\u001f\u0010&\u001a\u0004\u0018\u00010\"8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b#\u0010\u001f\u001a\u0004\b$\u0010%R\u001d\u0010+\u001a\u00020'8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b(\u0010\u001f\u001a\u0004\b)\u0010*R\u001d\u00100\u001a\u00020,8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b-\u0010\u001f\u001a\u0004\b.\u0010/¨\u00063"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/web/WebActivity;", "Lcom/qunidayede/supportlibrary/core/view/BaseActivity;", "", "initWebView", "()V", "Landroid/webkit/WebView;", "webView", "fullReleaseWebView", "(Landroid/webkit/WebView;)V", "", "getLayoutId", "()I", "bindEvent", "onPause", "releaseResources", "onBackPressed", "Landroid/webkit/ValueCallback;", "", "Landroid/net/Uri;", "mFilePathCallbacks", "Landroid/webkit/ValueCallback;", "getMFilePathCallbacks", "()Landroid/webkit/ValueCallback;", "setMFilePathCallbacks", "(Landroid/webkit/ValueCallback;)V", "Landroidx/activity/result/ActivityResultLauncher;", "Landroid/content/Intent;", "kotlin.jvm.PlatformType", "launcher", "Landroidx/activity/result/ActivityResultLauncher;", "webView$delegate", "Lkotlin/Lazy;", "getWebView", "()Landroid/webkit/WebView;", "", "url$delegate", "getUrl", "()Ljava/lang/String;", "url", "Landroid/widget/FrameLayout;", "web_container$delegate", "getWeb_container", "()Landroid/widget/FrameLayout;", "web_container", "Landroid/webkit/WebSettings;", "webSettings$delegate", "getWebSettings", "()Landroid/webkit/WebSettings;", "webSettings", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class WebActivity extends BaseActivity {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    @NotNull
    private final ActivityResultLauncher<Intent> launcher;

    @Nullable
    private ValueCallback<Uri[]> mFilePathCallbacks;

    /* renamed from: web_container$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy web_container;

    /* renamed from: url$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy url = LazyKt__LazyJVMKt.lazy(new Function0<String>() { // from class: com.jbzd.media.movecartoons.ui.web.WebActivity$url$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @Nullable
        public final String invoke() {
            return WebActivity.this.getIntent().getStringExtra("KEY_URL");
        }
    });

    /* renamed from: webView$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy webView = LazyKt__LazyJVMKt.lazy(new Function0<WebView>() { // from class: com.jbzd.media.movecartoons.ui.web.WebActivity$webView$2
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
    private final Lazy webSettings = LazyKt__LazyJVMKt.lazy(new Function0<WebSettings>() { // from class: com.jbzd.media.movecartoons.ui.web.WebActivity$webSettings$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final WebSettings invoke() {
            return WebActivity.this.getWebView().getSettings();
        }
    });

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u001c\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0007\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u000b\u0010\fJ\u001d\u0010\u0007\u001a\u00020\u00062\u0006\u0010\u0003\u001a\u00020\u00022\u0006\u0010\u0005\u001a\u00020\u0004¢\u0006\u0004\b\u0007\u0010\bJ\u0015\u0010\t\u001a\u00020\u00062\u0006\u0010\u0003\u001a\u00020\u0002¢\u0006\u0004\b\t\u0010\n¨\u0006\r"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/web/WebActivity$Companion;", "", "Landroid/content/Context;", "context", "", "url", "", "start", "(Landroid/content/Context;Ljava/lang/String;)V", "finish", "(Landroid/content/Context;)V", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public final void finish(@NotNull Context context) {
            Intrinsics.checkNotNullParameter(context, "context");
            ((WebActivity) context).finish();
        }

        public final void start(@NotNull Context context, @NotNull String url) {
            Intrinsics.checkNotNullParameter(context, "context");
            Intrinsics.checkNotNullParameter(url, "url");
            Intent intent = new Intent(context, (Class<?>) WebActivity.class);
            intent.putExtra("KEY_URL", url);
            Unit unit = Unit.INSTANCE;
            context.startActivity(intent);
        }
    }

    public WebActivity() {
        ActivityResultLauncher<Intent> registerForActivityResult = registerForActivityResult(new ActivityResultContracts.StartActivityForResult(), new ActivityResultCallback() { // from class: b.a.a.a.t.s.c
            @Override // androidx.activity.result.ActivityResultCallback
            public final void onActivityResult(Object obj) {
                WebActivity.m6022launcher$lambda0(WebActivity.this, (ActivityResult) obj);
            }
        });
        Intrinsics.checkNotNullExpressionValue(registerForActivityResult, "registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->\n            if (result.resultCode == RESULT_OK) {\n                val list = FileChooserParams.parseResult(result.resultCode, result.data)\n                mFilePathCallbacks?.onReceiveValue(list)\n            } else {\n                mFilePathCallbacks?.onReceiveValue(null)\n            }\n            mFilePathCallbacks = null\n        }");
        this.launcher = registerForActivityResult;
        this.web_container = LazyKt__LazyJVMKt.lazy(new Function0<FrameLayout>() { // from class: com.jbzd.media.movecartoons.ui.web.WebActivity$web_container$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final FrameLayout invoke() {
                FrameLayout frameLayout = (FrameLayout) WebActivity.this.findViewById(R.id.web_container);
                Intrinsics.checkNotNull(frameLayout);
                return frameLayout;
            }
        });
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
        getWebSettings().setAppCachePath(getApplicationContext().getCacheDir().getAbsolutePath());
        getWebSettings().setAllowFileAccess(true);
        getWebSettings().setAppCacheEnabled(true);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: launcher$lambda-0, reason: not valid java name */
    public static final void m6022launcher$lambda0(WebActivity this$0, ActivityResult activityResult) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        if (activityResult.getResultCode() == -1) {
            Uri[] parseResult = WebChromeClient.FileChooserParams.parseResult(activityResult.getResultCode(), activityResult.getData());
            ValueCallback<Uri[]> mFilePathCallbacks = this$0.getMFilePathCallbacks();
            if (mFilePathCallbacks != null) {
                mFilePathCallbacks.onReceiveValue(parseResult);
            }
        } else {
            ValueCallback<Uri[]> mFilePathCallbacks2 = this$0.getMFilePathCallbacks();
            if (mFilePathCallbacks2 != null) {
                mFilePathCallbacks2.onReceiveValue(null);
            }
        }
        this$0.setMFilePathCallbacks(null);
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseActivity
    public void _$_clearFindViewByIdCache() {
    }

    @Override // p005b.p327w.p330b.p331b.p334e.InterfaceC2847j
    public void bindEvent() {
        String url;
        String str;
        getWeb_container().addView(getWebView(), 0, new ViewGroup.LayoutParams(-1, -1));
        initWebView();
        getWebView().setWebChromeClient(new WebChromeClient() { // from class: com.jbzd.media.movecartoons.ui.web.WebActivity$bindEvent$1
            @Override // android.webkit.WebChromeClient
            public boolean onShowFileChooser(@Nullable WebView webView, @Nullable ValueCallback<Uri[]> filePathCallback, @Nullable WebChromeClient.FileChooserParams fileChooserParams) {
                ActivityResultLauncher activityResultLauncher;
                WebActivity.this.setMFilePathCallbacks(filePathCallback);
                if (fileChooserParams == null) {
                    return true;
                }
                activityResultLauncher = WebActivity.this.launcher;
                Intent createIntent = fileChooserParams.createIntent();
                createIntent.setType("image/*");
                Unit unit = Unit.INSTANCE;
                activityResultLauncher.launch(createIntent);
                return true;
            }
        });
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
        return R.layout.web_act;
    }

    @Nullable
    public final ValueCallback<Uri[]> getMFilePathCallbacks() {
        return this.mFilePathCallbacks;
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

    @Override // androidx.activity.ComponentActivity, android.app.Activity
    public void onBackPressed() {
        if (getWebView().canGoBack()) {
            getWebView().goBack();
        } else {
            super.onBackPressed();
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

    public final void setMFilePathCallbacks(@Nullable ValueCallback<Uri[]> valueCallback) {
        this.mFilePathCallbacks = valueCallback;
    }
}
