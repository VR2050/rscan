package p005b.p327w.p330b.p331b.p332c;

import android.R;
import android.app.Activity;
import android.app.Dialog;
import android.content.res.TypedArray;
import android.view.View;
import android.view.ViewStub;
import android.view.Window;
import android.view.WindowManager;
import android.widget.FrameLayout;
import androidx.core.view.InputDeviceCompat;
import com.gyf.immersionbar.ImmersionBar;
import com.qunidayede.supportlibrary.R$id;
import com.qunidayede.supportlibrary.R$layout;
import com.qunidayede.supportlibrary.R$style;
import com.qunidayede.supportlibrary.databinding.ViewRootBinding;
import com.qunidayede.supportlibrary.widget.LoadingView;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

/* renamed from: b.w.b.b.c.b */
/* loaded from: classes2.dex */
public final class C2831b {

    /* renamed from: a */
    @NotNull
    public final Activity f7675a;

    /* renamed from: b */
    @NotNull
    public final ViewRootBinding f7676b;

    /* renamed from: c */
    @Nullable
    public Dialog f7677c;

    /* renamed from: d */
    public boolean f7678d;

    /* renamed from: e */
    public FrameLayout f7679e;

    /* renamed from: f */
    public LoadingView f7680f;

    public C2831b(@NotNull Activity activity, @NotNull ViewRootBinding rootBinding) {
        Intrinsics.checkNotNullParameter(activity, "activity");
        Intrinsics.checkNotNullParameter(rootBinding, "rootBinding");
        this.f7675a = activity;
        this.f7676b = rootBinding;
    }

    /* renamed from: a */
    public final void m3283a() {
        Dialog dialog = this.f7677c;
        if (dialog != null) {
            dialog.dismiss();
            this.f7677c = null;
        }
        if (this.f7678d) {
            FrameLayout frameLayout = this.f7679e;
            if (frameLayout != null) {
                frameLayout.setVisibility(8);
            } else {
                Intrinsics.throwUninitializedPropertyAccessException("loadingFrame");
                throw null;
            }
        }
    }

    /* renamed from: b */
    public final void m3284b() {
        Dialog dialog = this.f7677c;
        if (dialog != null && dialog.isShowing()) {
            return;
        }
        Dialog dialog2 = new Dialog(this.f7675a, R$style.loading_dialog_theme);
        this.f7677c = dialog2;
        if (dialog2 == null) {
            return;
        }
        dialog2.setCancelable(false);
        dialog2.setContentView(R$layout.layout_loading);
        FrameLayout frameLayout = (FrameLayout) dialog2.findViewById(R$id.loading_frame);
        LoadingView loadingView = (LoadingView) dialog2.findViewById(R$id.loading_view);
        frameLayout.setVisibility(0);
        TypedArray obtainStyledAttributes = this.f7675a.getTheme().obtainStyledAttributes(new int[]{R.attr.colorAccent});
        Intrinsics.checkNotNullExpressionValue(obtainStyledAttributes, "activity.theme.obtainStyledAttributes(\n                intArrayOf(\n                    android.R.attr.colorAccent\n                )\n            )");
        loadingView.setLoadColor(obtainStyledAttributes.getColor(0, -7829368));
        obtainStyledAttributes.recycle();
        ImmersionBar.with(this.f7675a, dialog2).transparentStatusBar().init();
        dialog2.show();
        Window window = dialog2.getWindow();
        if (window == null) {
            return;
        }
        WindowManager.LayoutParams attributes = window.getAttributes();
        attributes.width = -1;
        attributes.height = -1;
        View decorView = window.getDecorView();
        Intrinsics.checkNotNullExpressionValue(decorView, "decorView");
        decorView.setPadding(0, 0, 0, 0);
        window.setAttributes(attributes);
    }

    /* renamed from: c */
    public final void m3285c() {
        FrameLayout frameLayout = this.f7676b.layoutBody;
        TypedArray obtainStyledAttributes = this.f7675a.getTheme().obtainStyledAttributes(new int[]{R.attr.colorBackground, R.attr.colorAccent});
        Intrinsics.checkNotNullExpressionValue(obtainStyledAttributes, "activity.theme.obtainStyledAttributes(\n                intArrayOf(\n                    android.R.attr.colorBackground,\n                    android.R.attr.colorAccent\n                )\n            )");
        if (this.f7678d) {
            FrameLayout frameLayout2 = this.f7679e;
            if (frameLayout2 == null) {
                Intrinsics.throwUninitializedPropertyAccessException("loadingFrame");
                throw null;
            }
            frameLayout2.setVisibility(0);
            FrameLayout frameLayout3 = this.f7679e;
            if (frameLayout3 == null) {
                Intrinsics.throwUninitializedPropertyAccessException("loadingFrame");
                throw null;
            }
            frameLayout3.setBackgroundColor(InputDeviceCompat.SOURCE_ANY);
            LoadingView loadingView = this.f7680f;
            if (loadingView == null) {
                Intrinsics.throwUninitializedPropertyAccessException("loadingView");
                throw null;
            }
            loadingView.setLoadColor(-7829368);
        } else {
            this.f7676b.loadingViewStub.setOnInflateListener(new ViewStub.OnInflateListener() { // from class: b.w.b.b.c.a
                @Override // android.view.ViewStub.OnInflateListener
                public final void onInflate(ViewStub viewStub, View view) {
                    C2831b this$0 = C2831b.this;
                    Intrinsics.checkNotNullParameter(this$0, "this$0");
                    this$0.f7678d = true;
                    View findViewById = view.findViewById(R$id.loading_frame);
                    Intrinsics.checkNotNullExpressionValue(findViewById, "view.findViewById(R.id.loading_frame)");
                    FrameLayout frameLayout4 = (FrameLayout) findViewById;
                    this$0.f7679e = frameLayout4;
                    if (frameLayout4 == null) {
                        Intrinsics.throwUninitializedPropertyAccessException("loadingFrame");
                        throw null;
                    }
                    frameLayout4.setVisibility(0);
                    FrameLayout frameLayout5 = this$0.f7679e;
                    if (frameLayout5 == null) {
                        Intrinsics.throwUninitializedPropertyAccessException("loadingFrame");
                        throw null;
                    }
                    frameLayout5.setBackgroundColor(-1);
                    View findViewById2 = view.findViewById(R$id.loading_view);
                    Intrinsics.checkNotNullExpressionValue(findViewById2, "view.findViewById(R.id.loading_view)");
                    LoadingView loadingView2 = (LoadingView) findViewById2;
                    this$0.f7680f = loadingView2;
                    if (loadingView2 != null) {
                        loadingView2.setLoadColor(-7829368);
                    } else {
                        Intrinsics.throwUninitializedPropertyAccessException("loadingView");
                        throw null;
                    }
                }
            });
            this.f7676b.loadingViewStub.inflate();
        }
        obtainStyledAttributes.recycle();
    }
}
