package com.jbzd.media.movecartoons.p396ui.settings;

import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.widget.ImageView;
import android.widget.TextView;
import com.gyf.immersionbar.ImmersionBar;
import com.jbzd.media.movecartoons.R$id;
import com.jbzd.media.movecartoons.databinding.ActRegisterInputBinding;
import com.qnmd.adnnm.da0yzo.R;
import com.qunidayede.supportlibrary.core.view.BaseBindingActivity;
import com.qunidayede.supportlibrary.core.view.BaseVMActivity;
import com.qunidayede.supportlibrary.databinding.TitleBarLayoutBinding;
import com.qunidayede.supportlibrary.widget.CommonShapeButton;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt__StringsJVMKt;
import org.jetbrains.annotations.Nullable;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p327w.p330b.C2827a;
import p005b.p327w.p330b.p331b.ApplicationC2828a;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000(\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010\u000b\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0005\u0018\u00002\u000e\u0012\u0004\u0012\u00020\u0002\u0012\u0004\u0012\u00020\u00030\u0001B\u0007¢\u0006\u0004\b\u000f\u0010\u0006J\u000f\u0010\u0005\u001a\u00020\u0004H\u0016¢\u0006\u0004\b\u0005\u0010\u0006J\u000f\u0010\b\u001a\u00020\u0007H\u0016¢\u0006\u0004\b\b\u0010\tJ\u000f\u0010\n\u001a\u00020\u0007H\u0016¢\u0006\u0004\b\n\u0010\tJ\u0019\u0010\r\u001a\u00020\u00042\b\u0010\f\u001a\u0004\u0018\u00010\u000bH\u0014¢\u0006\u0004\b\r\u0010\u000e¨\u0006\u0010"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/settings/RegisterActivity;", "Lcom/qunidayede/supportlibrary/core/view/BaseVMActivity;", "Lcom/jbzd/media/movecartoons/databinding/ActRegisterInputBinding;", "Lcom/jbzd/media/movecartoons/ui/settings/SignViewModel;", "", "bindEvent", "()V", "", "immersionBar", "()Z", "showHomeAsUp", "Landroid/os/Bundle;", "savedInstanceState", "onCreate", "(Landroid/os/Bundle;)V", "<init>", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class RegisterActivity extends BaseVMActivity<ActRegisterInputBinding, SignViewModel> {
    @Override // com.qunidayede.supportlibrary.core.view.BaseVMActivity, com.qunidayede.supportlibrary.core.view.BaseBindingActivity
    public void _$_clearFindViewByIdCache() {
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseBindingActivity, p005b.p327w.p330b.p331b.p334e.InterfaceC2847j
    public void bindEvent() {
        TextView textView;
        super.bindEvent();
        TitleBarLayoutBinding titleBarBinding = getTitleBarBinding();
        if (titleBarBinding != null && (textView = titleBarBinding.tvTitle) != null) {
            textView.setTextColor(getResources().getColor(R.color.white));
        }
        TitleBarLayoutBinding titleBarBinding2 = getTitleBarBinding();
        TextView textView2 = titleBarBinding2 == null ? null : titleBarBinding2.tvTitle;
        if (textView2 == null) {
            return;
        }
        textView2.setText("注册");
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseBindingActivity
    public boolean immersionBar() {
        return true;
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseVMActivity, com.qunidayede.supportlibrary.core.view.BaseBindingActivity, androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    public void onCreate(@Nullable Bundle savedInstanceState) {
        String str;
        super.onCreate(savedInstanceState);
        ImmersionBar with = ImmersionBar.with(this);
        Intrinsics.checkExpressionValueIsNotNull(with, "this");
        with.statusBarDarkFont(false);
        with.init();
        ((ImageView) getTitleLayout().findViewById(R.id.iv_titleLeftIcon)).setColorFilter(-1);
        CommonShapeButton btn_register_now = (CommonShapeButton) findViewById(R$id.btn_register_now);
        Intrinsics.checkNotNullExpressionValue(btn_register_now, "btn_register_now");
        BaseBindingActivity.fadeWhenTouch$default(this, btn_register_now, 0.0f, 1, null);
        ApplicationC2828a context = C2827a.f7670a;
        if (context == null) {
            Intrinsics.throwUninitializedPropertyAccessException("context");
            throw null;
        }
        Intrinsics.checkNotNullParameter(context, "context");
        try {
            PackageManager packageManager = context.getPackageManager();
            ApplicationInfo applicationInfo = packageManager.getApplicationInfo(context.getPackageName(), 128);
            Intrinsics.checkNotNullExpressionValue(applicationInfo, "manager.getApplicationInfo(context.packageName, PackageManager.GET_META_DATA)");
            str = (String) packageManager.getApplicationLabel(applicationInfo);
        } catch (PackageManager.NameNotFoundException unused) {
            str = "";
        }
        if (Intrinsics.areEqual(str != null ? Boolean.valueOf(StringsKt__StringsJVMKt.startsWith$default(str, "九妖", false, 2, null)) : null, Boolean.TRUE)) {
            C2354n.m2467d2(this).m3297o(Integer.valueOf(R.drawable.user_login_header_51)).m3295i0().m757R((ImageView) findViewById(R$id.iv_header));
        } else {
            C2354n.m2467d2(this).m3297o(Integer.valueOf(R.drawable.user_login_header)).m3295i0().m757R((ImageView) findViewById(R$id.iv_header));
        }
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseBindingActivity
    public boolean showHomeAsUp() {
        return true;
    }
}
