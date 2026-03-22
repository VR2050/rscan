package com.jbzd.media.movecartoons.p396ui.settings;

import android.content.Context;
import android.os.Bundle;
import android.widget.ImageView;
import android.widget.TextView;
import com.gyf.immersionbar.ImmersionBar;
import com.jbzd.media.movecartoons.MyApp;
import com.jbzd.media.movecartoons.databinding.ActLoginInputBinding;
import com.qnmd.adnnm.da0yzo.R;
import com.qunidayede.supportlibrary.core.view.BaseBindingActivity;
import com.qunidayede.supportlibrary.core.view.BaseVMActivity;
import com.qunidayede.supportlibrary.databinding.TitleBarLayoutBinding;
import com.qunidayede.supportlibrary.widget.CommonShapeButton;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000@\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010\u000b\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\r\u0018\u0000 &2\u000e\u0012\u0004\u0012\u00020\u0002\u0012\u0004\u0012\u00020\u00030\u0001:\u0001&B\u0007¢\u0006\u0004\b%\u0010\u0006J\u000f\u0010\u0005\u001a\u00020\u0004H\u0016¢\u0006\u0004\b\u0005\u0010\u0006J\u000f\u0010\b\u001a\u00020\u0007H\u0016¢\u0006\u0004\b\b\u0010\tJ\u000f\u0010\n\u001a\u00020\u0007H\u0016¢\u0006\u0004\b\n\u0010\tJ\u0019\u0010\r\u001a\u00020\u00042\b\u0010\f\u001a\u0004\u0018\u00010\u000bH\u0014¢\u0006\u0004\b\r\u0010\u000eR\u001d\u0010\u0014\u001a\u00020\u000f8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u0010\u0010\u0011\u001a\u0004\b\u0012\u0010\u0013R\u001d\u0010\u0019\u001a\u00020\u00158F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u0016\u0010\u0011\u001a\u0004\b\u0017\u0010\u0018R\u001d\u0010\u001e\u001a\u00020\u001a8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u001b\u0010\u0011\u001a\u0004\b\u001c\u0010\u001dR\u001d\u0010!\u001a\u00020\u000f8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u001f\u0010\u0011\u001a\u0004\b \u0010\u0013R\u001d\u0010$\u001a\u00020\u000f8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\"\u0010\u0011\u001a\u0004\b#\u0010\u0013¨\u0006'"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/settings/LoginActivity;", "Lcom/qunidayede/supportlibrary/core/view/BaseVMActivity;", "Lcom/jbzd/media/movecartoons/databinding/ActLoginInputBinding;", "Lcom/jbzd/media/movecartoons/ui/settings/SignViewModel;", "", "bindEvent", "()V", "", "immersionBar", "()Z", "showHomeAsUp", "Landroid/os/Bundle;", "savedInstanceState", "onCreate", "(Landroid/os/Bundle;)V", "Landroid/widget/TextView;", "tv_scancode_login$delegate", "Lkotlin/Lazy;", "getTv_scancode_login", "()Landroid/widget/TextView;", "tv_scancode_login", "Landroid/widget/ImageView;", "iv_header$delegate", "getIv_header", "()Landroid/widget/ImageView;", "iv_header", "Lcom/qunidayede/supportlibrary/widget/CommonShapeButton;", "btn_login_now$delegate", "getBtn_login_now", "()Lcom/qunidayede/supportlibrary/widget/CommonShapeButton;", "btn_login_now", "tv_account_login_tips$delegate", "getTv_account_login_tips", "tv_account_login_tips", "txt_sign_now$delegate", "getTxt_sign_now", "txt_sign_now", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class LoginActivity extends BaseVMActivity<ActLoginInputBinding, SignViewModel> {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    /* renamed from: tv_account_login_tips$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_account_login_tips = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.settings.LoginActivity$tv_account_login_tips$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            TextView textView = (TextView) LoginActivity.this.findViewById(R.id.tv_account_login_tips);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    /* renamed from: btn_login_now$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy btn_login_now = LazyKt__LazyJVMKt.lazy(new Function0<CommonShapeButton>() { // from class: com.jbzd.media.movecartoons.ui.settings.LoginActivity$btn_login_now$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final CommonShapeButton invoke() {
            CommonShapeButton commonShapeButton = (CommonShapeButton) LoginActivity.this.findViewById(R.id.btn_login_now);
            Intrinsics.checkNotNull(commonShapeButton);
            return commonShapeButton;
        }
    });

    /* renamed from: txt_sign_now$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy txt_sign_now = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.settings.LoginActivity$txt_sign_now$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            TextView textView = (TextView) LoginActivity.this.findViewById(R.id.txt_sign_now);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    /* renamed from: tv_scancode_login$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_scancode_login = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.settings.LoginActivity$tv_scancode_login$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            TextView textView = (TextView) LoginActivity.this.findViewById(R.id.tv_scancode_login);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    /* renamed from: iv_header$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy iv_header = LazyKt__LazyJVMKt.lazy(new Function0<ImageView>() { // from class: com.jbzd.media.movecartoons.ui.settings.LoginActivity$iv_header$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ImageView invoke() {
            ImageView imageView = (ImageView) LoginActivity.this.findViewById(R.id.iv_header);
            Intrinsics.checkNotNull(imageView);
            return imageView;
        }
    });

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0016\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0005\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0007\u0010\bJ\u0015\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0003\u001a\u00020\u0002¢\u0006\u0004\b\u0005\u0010\u0006¨\u0006\t"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/settings/LoginActivity$Companion;", "", "Landroid/content/Context;", "context", "", "start", "(Landroid/content/Context;)V", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public final void start(@NotNull Context context) {
            C1499a.m602X(context, "context", context, LoginActivity.class);
        }
    }

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
        textView2.setText("登录");
    }

    @NotNull
    public final CommonShapeButton getBtn_login_now() {
        return (CommonShapeButton) this.btn_login_now.getValue();
    }

    @NotNull
    public final ImageView getIv_header() {
        return (ImageView) this.iv_header.getValue();
    }

    @NotNull
    public final TextView getTv_account_login_tips() {
        return (TextView) this.tv_account_login_tips.getValue();
    }

    @NotNull
    public final TextView getTv_scancode_login() {
        return (TextView) this.tv_scancode_login.getValue();
    }

    @NotNull
    public final TextView getTxt_sign_now() {
        return (TextView) this.txt_sign_now.getValue();
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseBindingActivity
    public boolean immersionBar() {
        return true;
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseVMActivity, com.qunidayede.supportlibrary.core.view.BaseBindingActivity, androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    public void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        ImmersionBar with = ImmersionBar.with(this);
        Intrinsics.checkExpressionValueIsNotNull(with, "this");
        with.statusBarDarkFont(false);
        with.init();
        ((ImageView) getTitleLayout().findViewById(R.id.iv_titleLeftIcon)).setColorFilter(-1);
        TextView tv_account_login_tips = getTv_account_login_tips();
        MyApp myApp = MyApp.f9891f;
        tv_account_login_tips.setText(MyApp.m4185f().account_login_tips);
        BaseBindingActivity.fadeWhenTouch$default(this, getBtn_login_now(), 0.0f, 1, null);
        BaseBindingActivity.fadeWhenTouch$default(this, getTxt_sign_now(), 0.0f, 1, null);
        BaseBindingActivity.fadeWhenTouch$default(this, getTv_scancode_login(), 0.0f, 1, null);
        C2354n.m2467d2(this).m3297o(Integer.valueOf(R.drawable.user_login_header)).m3295i0().m757R(getIv_header());
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseBindingActivity
    public boolean showHomeAsUp() {
        return true;
    }
}
