package com.jbzd.media.movecartoons.p396ui.dialog;

import android.annotation.SuppressLint;
import android.app.Dialog;
import android.content.Context;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.view.WindowManager;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.widget.AppCompatEditText;
import androidx.fragment.app.DialogFragment;
import com.jbzd.media.movecartoons.MyApp;
import com.jbzd.media.movecartoons.bean.response.UserInfoBean;
import com.jbzd.media.movecartoons.p396ui.vip.BuyActivity;
import com.jbzd.media.movecartoons.view.GradientRoundCornerButton;
import com.qnmd.adnnm.da0yzo.R;
import java.util.Objects;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt__StringsKt;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p006a.p007a.p008a.p017r.C0917a;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000^\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u000f\n\u0002\u0018\u0002\n\u0002\u0010\u000e\n\u0002\u0018\u0002\n\u0002\b\n\u0018\u00002\u00020\u0001B?\u00126\u00109\u001a2\u0012\u0013\u0012\u001104¢\u0006\f\b5\u0012\b\b6\u0012\u0004\b\b(7\u0012\u0013\u0012\u001104¢\u0006\f\b5\u0012\b\b6\u0012\u0004\b\b(8\u0012\u0004\u0012\u00020\u000503¢\u0006\u0004\b=\u0010>J\u000f\u0010\u0003\u001a\u00020\u0002H\u0002¢\u0006\u0004\b\u0003\u0010\u0004J\u000f\u0010\u0006\u001a\u00020\u0005H\u0017¢\u0006\u0004\b\u0006\u0010\u0007J\u0019\u0010\u000b\u001a\u00020\n2\b\u0010\t\u001a\u0004\u0018\u00010\bH\u0016¢\u0006\u0004\b\u000b\u0010\fJ!\u0010\u000f\u001a\u00020\u00052\u0006\u0010\u000e\u001a\u00020\r2\b\u0010\t\u001a\u0004\u0018\u00010\bH\u0016¢\u0006\u0004\b\u000f\u0010\u0010J\u0019\u0010\u0011\u001a\u00020\u00052\b\u0010\t\u001a\u0004\u0018\u00010\bH\u0016¢\u0006\u0004\b\u0011\u0010\u0012R\u001d\u0010\u0018\u001a\u00020\u00138B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u0014\u0010\u0015\u001a\u0004\b\u0016\u0010\u0017R\u001d\u0010\u001d\u001a\u00020\u00198B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u001a\u0010\u0015\u001a\u0004\b\u001b\u0010\u001cR\u001d\u0010\"\u001a\u00020\u001e8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u001f\u0010\u0015\u001a\u0004\b \u0010!R\u001d\u0010'\u001a\u00020#8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b$\u0010\u0015\u001a\u0004\b%\u0010&R\u001d\u0010*\u001a\u00020\u00028B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b(\u0010\u0015\u001a\u0004\b)\u0010\u0004R%\u0010/\u001a\n +*\u0004\u0018\u00010\r0\r8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b,\u0010\u0015\u001a\u0004\b-\u0010.R\u001d\u00102\u001a\u00020\u00198B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b0\u0010\u0015\u001a\u0004\b1\u0010\u001cRI\u00109\u001a2\u0012\u0013\u0012\u001104¢\u0006\f\b5\u0012\b\b6\u0012\u0004\b\b(7\u0012\u0013\u0012\u001104¢\u0006\f\b5\u0012\b\b6\u0012\u0004\b\b(8\u0012\u0004\u0012\u00020\u0005038\u0006@\u0006¢\u0006\f\n\u0004\b9\u0010:\u001a\u0004\b;\u0010<¨\u0006?"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/dialog/PostCoinDialog;", "Landroidx/fragment/app/DialogFragment;", "Landroidx/appcompat/app/AlertDialog;", "createDialog", "()Landroidx/appcompat/app/AlertDialog;", "", "onStart", "()V", "Landroid/os/Bundle;", "savedInstanceState", "Landroid/app/Dialog;", "onCreateDialog", "(Landroid/os/Bundle;)Landroid/app/Dialog;", "Landroid/view/View;", "view", "onViewCreated", "(Landroid/view/View;Landroid/os/Bundle;)V", "onActivityCreated", "(Landroid/os/Bundle;)V", "Landroid/widget/TextView;", "tvBalance$delegate", "Lkotlin/Lazy;", "getTvBalance", "()Landroid/widget/TextView;", "tvBalance", "Landroidx/appcompat/widget/AppCompatEditText;", "etDoc$delegate", "getEtDoc", "()Landroidx/appcompat/widget/AppCompatEditText;", "etDoc", "Lcom/jbzd/media/movecartoons/view/GradientRoundCornerButton;", "btn$delegate", "getBtn", "()Lcom/jbzd/media/movecartoons/view/GradientRoundCornerButton;", "btn", "Landroid/widget/ImageView;", "btnClose$delegate", "getBtnClose", "()Landroid/widget/ImageView;", "btnClose", "alertDialog$delegate", "getAlertDialog", "alertDialog", "kotlin.jvm.PlatformType", "contentView$delegate", "getContentView", "()Landroid/view/View;", "contentView", "etCoin$delegate", "getEtCoin", "etCoin", "Lkotlin/Function2;", "", "Lkotlin/ParameterName;", "name", "coin", "doc", "submit", "Lkotlin/jvm/functions/Function2;", "getSubmit", "()Lkotlin/jvm/functions/Function2;", "<init>", "(Lkotlin/jvm/functions/Function2;)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class PostCoinDialog extends DialogFragment {

    /* renamed from: alertDialog$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy alertDialog;

    /* renamed from: btn$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy btn;

    /* renamed from: btnClose$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy btnClose;

    /* renamed from: contentView$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy contentView;

    /* renamed from: etCoin$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy etCoin;

    /* renamed from: etDoc$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy etDoc;

    @NotNull
    private final Function2<String, String, Unit> submit;

    /* renamed from: tvBalance$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tvBalance;

    /* JADX WARN: Multi-variable type inference failed */
    public PostCoinDialog(@NotNull Function2<? super String, ? super String, Unit> submit) {
        Intrinsics.checkNotNullParameter(submit, "submit");
        this.submit = submit;
        this.contentView = LazyKt__LazyJVMKt.lazy(new Function0<View>() { // from class: com.jbzd.media.movecartoons.ui.dialog.PostCoinDialog$contentView$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            public final View invoke() {
                return LayoutInflater.from(PostCoinDialog.this.getContext()).inflate(R.layout.dialog_post_coin, (ViewGroup) null);
            }
        });
        this.tvBalance = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.dialog.PostCoinDialog$tvBalance$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final TextView invoke() {
                View contentView;
                contentView = PostCoinDialog.this.getContentView();
                View findViewById = contentView.findViewById(R.id.tvBalance);
                Objects.requireNonNull(findViewById, "null cannot be cast to non-null type android.widget.TextView");
                return (TextView) findViewById;
            }
        });
        this.etCoin = LazyKt__LazyJVMKt.lazy(new Function0<AppCompatEditText>() { // from class: com.jbzd.media.movecartoons.ui.dialog.PostCoinDialog$etCoin$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final AppCompatEditText invoke() {
                View contentView;
                contentView = PostCoinDialog.this.getContentView();
                View findViewById = contentView.findViewById(R.id.etCoin);
                Objects.requireNonNull(findViewById, "null cannot be cast to non-null type androidx.appcompat.widget.AppCompatEditText");
                return (AppCompatEditText) findViewById;
            }
        });
        this.etDoc = LazyKt__LazyJVMKt.lazy(new Function0<AppCompatEditText>() { // from class: com.jbzd.media.movecartoons.ui.dialog.PostCoinDialog$etDoc$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final AppCompatEditText invoke() {
                View contentView;
                contentView = PostCoinDialog.this.getContentView();
                View findViewById = contentView.findViewById(R.id.etDoc);
                Objects.requireNonNull(findViewById, "null cannot be cast to non-null type androidx.appcompat.widget.AppCompatEditText");
                return (AppCompatEditText) findViewById;
            }
        });
        this.btn = LazyKt__LazyJVMKt.lazy(new Function0<GradientRoundCornerButton>() { // from class: com.jbzd.media.movecartoons.ui.dialog.PostCoinDialog$btn$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final GradientRoundCornerButton invoke() {
                View contentView;
                contentView = PostCoinDialog.this.getContentView();
                View findViewById = contentView.findViewById(R.id.btn);
                Objects.requireNonNull(findViewById, "null cannot be cast to non-null type com.jbzd.media.movecartoons.view.GradientRoundCornerButton");
                return (GradientRoundCornerButton) findViewById;
            }
        });
        this.btnClose = LazyKt__LazyJVMKt.lazy(new Function0<ImageView>() { // from class: com.jbzd.media.movecartoons.ui.dialog.PostCoinDialog$btnClose$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final ImageView invoke() {
                View contentView;
                contentView = PostCoinDialog.this.getContentView();
                View findViewById = contentView.findViewById(R.id.btnClose);
                Objects.requireNonNull(findViewById, "null cannot be cast to non-null type android.widget.ImageView");
                return (ImageView) findViewById;
            }
        });
        this.alertDialog = LazyKt__LazyJVMKt.lazy(new Function0<AlertDialog>() { // from class: com.jbzd.media.movecartoons.ui.dialog.PostCoinDialog$alertDialog$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final AlertDialog invoke() {
                AlertDialog createDialog;
                createDialog = PostCoinDialog.this.createDialog();
                return createDialog;
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final AlertDialog createDialog() {
        AlertDialog m624j0 = C1499a.m624j0(new AlertDialog.Builder(requireContext(), R.style.dialog_center), getContentView(), "Builder(requireContext(), R.style.dialog_center)\n            .setView(contentView)\n            .create()");
        C2354n.m2374A(getBtn(), 0L, new Function1<GradientRoundCornerButton, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.PostCoinDialog$createDialog$1
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(GradientRoundCornerButton gradientRoundCornerButton) {
                invoke2(gradientRoundCornerButton);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull GradientRoundCornerButton it) {
                AppCompatEditText etCoin;
                AppCompatEditText etCoin2;
                AppCompatEditText etDoc;
                Intrinsics.checkNotNullParameter(it, "it");
                etCoin = PostCoinDialog.this.getEtCoin();
                if (String.valueOf(etCoin.getText()).length() == 0) {
                    C2354n.m2379B1("请输入打赏 金额");
                    return;
                }
                Function2<String, String, Unit> submit = PostCoinDialog.this.getSubmit();
                etCoin2 = PostCoinDialog.this.getEtCoin();
                String obj = StringsKt__StringsKt.trim((CharSequence) String.valueOf(etCoin2.getText())).toString();
                etDoc = PostCoinDialog.this.getEtDoc();
                submit.invoke(obj, StringsKt__StringsKt.trim((CharSequence) String.valueOf(etDoc.getText())).toString());
                PostCoinDialog.this.dismissAllowingStateLoss();
            }
        }, 1);
        C2354n.m2374A(getBtnClose(), 0L, new Function1<ImageView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.PostCoinDialog$createDialog$2
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(ImageView imageView) {
                invoke2(imageView);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull ImageView it) {
                Intrinsics.checkNotNullParameter(it, "it");
                PostCoinDialog.this.dismissAllowingStateLoss();
            }
        }, 1);
        C2354n.m2374A(getContentView().findViewById(R.id.btnWallet), 0L, new Function1<TextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.PostCoinDialog$createDialog$3
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(TextView textView) {
                invoke2(textView);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(TextView textView) {
                BuyActivity.Companion companion = BuyActivity.INSTANCE;
                Context requireContext = PostCoinDialog.this.requireContext();
                Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
                companion.start(requireContext);
            }
        }, 1);
        TextView tvBalance = getTvBalance();
        MyApp myApp = MyApp.f9891f;
        UserInfoBean userInfoBean = MyApp.f9892g;
        tvBalance.setText(Intrinsics.stringPlus("余额：", userInfoBean == null ? null : userInfoBean.point));
        Window window = m624j0.getWindow();
        if (window != null) {
            window.setDimAmount(0.0f);
        }
        WindowManager.LayoutParams attributes = window != null ? window.getAttributes() : null;
        if (attributes != null) {
            attributes.windowAnimations = R.style.BottomShowAnimation;
        }
        return m624j0;
    }

    private final AlertDialog getAlertDialog() {
        return (AlertDialog) this.alertDialog.getValue();
    }

    private final GradientRoundCornerButton getBtn() {
        return (GradientRoundCornerButton) this.btn.getValue();
    }

    private final ImageView getBtnClose() {
        return (ImageView) this.btnClose.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final View getContentView() {
        return (View) this.contentView.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final AppCompatEditText getEtCoin() {
        return (AppCompatEditText) this.etCoin.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final AppCompatEditText getEtDoc() {
        return (AppCompatEditText) this.etDoc.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final TextView getTvBalance() {
        return (TextView) this.tvBalance.getValue();
    }

    public void _$_clearFindViewByIdCache() {
    }

    @NotNull
    public final Function2<String, String, Unit> getSubmit() {
        return this.submit;
    }

    @Override // androidx.fragment.app.Fragment
    public void onActivityCreated(@Nullable Bundle savedInstanceState) {
        super.onActivityCreated(savedInstanceState);
    }

    @Override // androidx.fragment.app.DialogFragment
    @NotNull
    public Dialog onCreateDialog(@Nullable Bundle savedInstanceState) {
        return getAlertDialog();
    }

    @Override // androidx.fragment.app.DialogFragment, androidx.fragment.app.Fragment
    @SuppressLint({"SetTextI18n"})
    public void onStart() {
        super.onStart();
        C0917a.m221e(C0917a.f372a, "user/baseInfo", UserInfoBean.class, null, new Function1<UserInfoBean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.PostCoinDialog$onStart$1
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(UserInfoBean userInfoBean) {
                invoke2(userInfoBean);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable UserInfoBean userInfoBean) {
                TextView tvBalance;
                if (userInfoBean == null) {
                    return;
                }
                tvBalance = PostCoinDialog.this.getTvBalance();
                tvBalance.setText(Intrinsics.stringPlus("余额:", userInfoBean.point));
                MyApp myApp = MyApp.f9891f;
                MyApp.m4189j(userInfoBean);
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.PostCoinDialog$onStart$2
            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(Exception exc) {
                invoke2(exc);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull Exception it) {
                Intrinsics.checkNotNullParameter(it, "it");
            }
        }, false, false, null, false, 484);
    }

    @Override // androidx.fragment.app.Fragment
    public void onViewCreated(@NotNull View view, @Nullable Bundle savedInstanceState) {
        Intrinsics.checkNotNullParameter(view, "view");
        super.onViewCreated(view, savedInstanceState);
    }
}
