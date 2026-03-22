package com.jbzd.media.movecartoons.p396ui.index.home;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.provider.MediaStore;
import android.view.ViewGroup;
import android.view.ViewParent;
import android.webkit.JavascriptInterface;
import android.webkit.ValueCallback;
import android.webkit.WebChromeClient;
import android.webkit.WebSettings;
import android.webkit.WebView;
import androidx.activity.result.ActivityResult;
import androidx.activity.result.ActivityResultCallback;
import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.fragment.app.FragmentActivity;
import com.gyf.immersionbar.ImmersionBar;
import com.jbzd.media.movecartoons.MyApp;
import com.jbzd.media.movecartoons.bean.TokenBean;
import com.jbzd.media.movecartoons.bean.response.system.SystemInfoBean;
import com.jbzd.media.movecartoons.databinding.FragmentAiAreaWebBinding;
import com.jbzd.media.movecartoons.p396ui.index.home.AiAreaFragment;
import com.jbzd.media.movecartoons.p396ui.vip.VipActivity;
import com.qunidayede.supportlibrary.core.view.BaseBindingFragment;
import java.util.HashMap;
import java.util.Objects;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Pair;
import kotlin.TuplesKt;
import kotlin.collections.MapsKt__MapsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p006a.p007a.p008a.C0887j;
import p005b.p199l.p258c.C2480j;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u00006\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0007\n\u0002\u0018\u0002\n\u0002\u0010\u0011\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0006\u0018\u00002\b\u0012\u0004\u0012\u00020\u00020\u0001:\u0001\u0018B\u0007¢\u0006\u0004\b\u0017\u0010\tJ\u0019\u0010\u0006\u001a\u00020\u00052\b\u0010\u0004\u001a\u0004\u0018\u00010\u0003H\u0002¢\u0006\u0004\b\u0006\u0010\u0007J\u000f\u0010\b\u001a\u00020\u0005H\u0002¢\u0006\u0004\b\b\u0010\tJ\u000f\u0010\n\u001a\u00020\u0005H\u0016¢\u0006\u0004\b\n\u0010\tJ\u000f\u0010\u000b\u001a\u00020\u0005H\u0016¢\u0006\u0004\b\u000b\u0010\tJ\u000f\u0010\f\u001a\u00020\u0005H\u0016¢\u0006\u0004\b\f\u0010\tR$\u0010\u0010\u001a\u0010\u0012\n\u0012\b\u0012\u0004\u0012\u00020\u000f0\u000e\u0018\u00010\r8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\u0010\u0010\u0011R$\u0010\u0015\u001a\u0010\u0012\f\u0012\n \u0014*\u0004\u0018\u00010\u00130\u00130\u00128\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\b\u0015\u0010\u0016¨\u0006\u0019"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/index/home/AiAreaFragment;", "Lcom/qunidayede/supportlibrary/core/view/BaseBindingFragment;", "Lcom/jbzd/media/movecartoons/databinding/FragmentAiAreaWebBinding;", "Landroid/webkit/WebView;", "webView", "", "fullReleaseWebView", "(Landroid/webkit/WebView;)V", "releaseResources", "()V", "initViews", "onPause", "onDestroyView", "Landroid/webkit/ValueCallback;", "", "Landroid/net/Uri;", "currentFilePathCallback", "Landroid/webkit/ValueCallback;", "Landroidx/activity/result/ActivityResultLauncher;", "Landroid/content/Intent;", "kotlin.jvm.PlatformType", "launcher", "Landroidx/activity/result/ActivityResultLauncher;", "<init>", "MyJavascriptInterface", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class AiAreaFragment extends BaseBindingFragment<FragmentAiAreaWebBinding> {

    @Nullable
    private ValueCallback<Uri[]> currentFilePathCallback;

    @NotNull
    private final ActivityResultLauncher<Intent> launcher;

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000,\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\u000e\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0007\u0018\u00002\u00020\u0001B\u000f\u0012\u0006\u0010\u0010\u001a\u00020\u000f¢\u0006\u0004\b\u0014\u0010\u0015J\u000f\u0010\u0003\u001a\u00020\u0002H\u0007¢\u0006\u0004\b\u0003\u0010\u0004J\u000f\u0010\u0006\u001a\u00020\u0005H\u0007¢\u0006\u0004\b\u0006\u0010\u0007R9\u0010\u000e\u001a\u001e\u0012\u0004\u0012\u00020\u0002\u0012\u0004\u0012\u00020\u00020\bj\u000e\u0012\u0004\u0012\u00020\u0002\u0012\u0004\u0012\u00020\u0002`\t8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\n\u0010\u000b\u001a\u0004\b\f\u0010\rR\u0019\u0010\u0010\u001a\u00020\u000f8\u0006@\u0006¢\u0006\f\n\u0004\b\u0010\u0010\u0011\u001a\u0004\b\u0012\u0010\u0013¨\u0006\u0016"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/index/home/AiAreaFragment$MyJavascriptInterface;", "", "", "getUserInfoFromAndroid", "()Ljava/lang/String;", "", "onTapVip", "()V", "Ljava/util/HashMap;", "Lkotlin/collections/HashMap;", "dataObject$delegate", "Lkotlin/Lazy;", "getDataObject", "()Ljava/util/HashMap;", "dataObject", "Landroid/app/Activity;", "context", "Landroid/app/Activity;", "getContext", "()Landroid/app/Activity;", "<init>", "(Landroid/app/Activity;)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class MyJavascriptInterface {

        @NotNull
        private final Activity context;

        /* renamed from: dataObject$delegate, reason: from kotlin metadata */
        @NotNull
        private final Lazy dataObject;

        public MyJavascriptInterface(@NotNull Activity context) {
            Intrinsics.checkNotNullParameter(context, "context");
            this.context = context;
            this.dataObject = LazyKt__LazyJVMKt.lazy(new Function0<HashMap<String, String>>() { // from class: com.jbzd.media.movecartoons.ui.index.home.AiAreaFragment$MyJavascriptInterface$dataObject$2
                @Override // kotlin.jvm.functions.Function0
                @NotNull
                public final HashMap<String, String> invoke() {
                    Pair[] pairArr = new Pair[2];
                    pairArr[0] = TuplesKt.m5318to("device_id", C0887j.m211a());
                    StringBuilder sb = new StringBuilder();
                    MyApp myApp = MyApp.f9891f;
                    TokenBean m4186g = MyApp.m4186g();
                    sb.append((Object) (m4186g == null ? null : m4186g.token));
                    sb.append('_');
                    TokenBean m4186g2 = MyApp.m4186g();
                    sb.append((Object) (m4186g2 != null ? m4186g2.user_id : null));
                    pairArr[1] = TuplesKt.m5318to("token", sb.toString());
                    return MapsKt__MapsKt.hashMapOf(pairArr);
                }
            });
        }

        @NotNull
        public final Activity getContext() {
            return this.context;
        }

        @NotNull
        public final HashMap<String, String> getDataObject() {
            return (HashMap) this.dataObject.getValue();
        }

        @JavascriptInterface
        @NotNull
        public final String getUserInfoFromAndroid() {
            String m2853g = new C2480j().m2853g(getDataObject());
            Intrinsics.checkNotNullExpressionValue(m2853g, "Gson().toJson(dataObject)");
            return m2853g;
        }

        @JavascriptInterface
        public final void onTapVip() {
            VipActivity.INSTANCE.start(this.context);
        }
    }

    public AiAreaFragment() {
        ActivityResultLauncher<Intent> registerForActivityResult = registerForActivityResult(new ActivityResultContracts.StartActivityForResult(), new ActivityResultCallback() { // from class: b.a.a.a.t.g.k.a
            @Override // androidx.activity.result.ActivityResultCallback
            public final void onActivityResult(Object obj) {
                AiAreaFragment.m5827launcher$lambda3(AiAreaFragment.this, (ActivityResult) obj);
            }
        });
        Intrinsics.checkNotNullExpressionValue(registerForActivityResult, "registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->\n            if (result.resultCode == Activity.RESULT_OK) {\n                val uri = result.data?.data\n                currentFilePathCallback?.onReceiveValue(\n                    if (uri != null) arrayOf(uri) else null\n                )\n                currentFilePathCallback = null\n            } else {\n                currentFilePathCallback?.onReceiveValue(null)\n                currentFilePathCallback = null\n            }\n\n        }");
        this.launcher = registerForActivityResult;
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
        webView.removeAllViews();
        webView.destroy();
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: launcher$lambda-3, reason: not valid java name */
    public static final void m5827launcher$lambda3(AiAreaFragment this$0, ActivityResult activityResult) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        if (activityResult.getResultCode() != -1) {
            ValueCallback<Uri[]> valueCallback = this$0.currentFilePathCallback;
            if (valueCallback != null) {
                valueCallback.onReceiveValue(null);
            }
            this$0.currentFilePathCallback = null;
            return;
        }
        Intent data = activityResult.getData();
        Uri data2 = data == null ? null : data.getData();
        ValueCallback<Uri[]> valueCallback2 = this$0.currentFilePathCallback;
        if (valueCallback2 != null) {
            valueCallback2.onReceiveValue(data2 != null ? new Uri[]{data2} : null);
        }
        this$0.currentFilePathCallback = null;
    }

    private final void releaseResources() {
        fullReleaseWebView(getBodyBinding().webView);
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseBindingFragment, com.qunidayede.supportlibrary.core.view.BaseFragment
    public void _$_clearFindViewByIdCache() {
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseFragment
    public void initViews() {
        super.initViews();
        ImmersionBar with = ImmersionBar.with(this);
        Intrinsics.checkExpressionValueIsNotNull(with, "this");
        with.statusBarDarkFont(true);
        with.init();
        getBodyBinding().llWebTop.setPadding(0, ImmersionBar.getStatusBarHeight(this), 0, 0);
        WebSettings settings = getBodyBinding().webView.getSettings();
        settings.setJavaScriptEnabled(true);
        settings.setCacheMode(-1);
        settings.setDomStorageEnabled(true);
        settings.setAllowFileAccess(true);
        MyApp myApp = MyApp.f9891f;
        SystemInfoBean m4185f = MyApp.m4185f();
        String str = (m4185f == null ? null : m4185f.webview_ai_url).toString();
        WebView webView = getBodyBinding().webView;
        FragmentActivity requireActivity = requireActivity();
        Intrinsics.checkNotNullExpressionValue(requireActivity, "requireActivity()");
        webView.addJavascriptInterface(new MyJavascriptInterface(requireActivity), "Android");
        WebView webView2 = getBodyBinding().webView;
        if (webView2 != null) {
            webView2.setWebChromeClient(new WebChromeClient() { // from class: com.jbzd.media.movecartoons.ui.index.home.AiAreaFragment$initViews$3$1
                @Override // android.webkit.WebChromeClient
                public boolean onShowFileChooser(@Nullable WebView webView3, @NotNull ValueCallback<Uri[]> filePathCallback, @Nullable WebChromeClient.FileChooserParams fileChooserParams) {
                    ActivityResultLauncher activityResultLauncher;
                    Intrinsics.checkNotNullParameter(filePathCallback, "filePathCallback");
                    AiAreaFragment.this.currentFilePathCallback = filePathCallback;
                    Intent intent = new Intent("android.intent.action.PICK", MediaStore.Images.Media.EXTERNAL_CONTENT_URI);
                    intent.setType("image/*");
                    activityResultLauncher = AiAreaFragment.this.launcher;
                    activityResultLauncher.launch(intent);
                    return true;
                }
            });
        }
        webView.loadUrl(str);
    }

    @Override // androidx.fragment.app.Fragment
    public void onDestroyView() {
        super.onDestroyView();
    }

    @Override // androidx.fragment.app.Fragment
    public void onPause() {
        super.onPause();
    }
}
