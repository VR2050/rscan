package com.jbzd.media.movecartoons.p396ui.dialog;

import android.app.Dialog;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.view.WindowManager;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.appcompat.app.AlertDialog;
import androidx.fragment.app.DialogFragment;
import com.jbzd.media.movecartoons.view.GradientRoundCornerButton;
import com.qnmd.adnnm.da0yzo.R;
import java.util.Objects;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000T\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\n\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0010\u000e\n\u0002\b\u0007\n\u0002\u0018\u0002\n\u0002\b\u0007\u0018\u00002\u00020\u0001B!\u0012\b\b\u0002\u0010%\u001a\u00020$\u0012\u000e\b\u0002\u0010 \u001a\b\u0012\u0004\u0012\u00020\f0\u001f¢\u0006\u0004\b1\u00102J\u000f\u0010\u0003\u001a\u00020\u0002H\u0002¢\u0006\u0004\b\u0003\u0010\u0004J\u0019\u0010\b\u001a\u00020\u00072\b\u0010\u0006\u001a\u0004\u0018\u00010\u0005H\u0016¢\u0006\u0004\b\b\u0010\tJ!\u0010\r\u001a\u00020\f2\u0006\u0010\u000b\u001a\u00020\n2\b\u0010\u0006\u001a\u0004\u0018\u00010\u0005H\u0016¢\u0006\u0004\b\r\u0010\u000eR\u001d\u0010\u0014\u001a\u00020\u000f8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u0010\u0010\u0011\u001a\u0004\b\u0012\u0010\u0013R%\u0010\u0019\u001a\n \u0015*\u0004\u0018\u00010\n0\n8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u0016\u0010\u0011\u001a\u0004\b\u0017\u0010\u0018R\u001d\u0010\u001e\u001a\u00020\u001a8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u001b\u0010\u0011\u001a\u0004\b\u001c\u0010\u001dR\u001f\u0010 \u001a\b\u0012\u0004\u0012\u00020\f0\u001f8\u0006@\u0006¢\u0006\f\n\u0004\b \u0010!\u001a\u0004\b\"\u0010#R\u0019\u0010%\u001a\u00020$8\u0006@\u0006¢\u0006\f\n\u0004\b%\u0010&\u001a\u0004\b'\u0010(R\u001d\u0010+\u001a\u00020\u00028B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b)\u0010\u0011\u001a\u0004\b*\u0010\u0004R\u001d\u00100\u001a\u00020,8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b-\u0010\u0011\u001a\u0004\b.\u0010/¨\u00063"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/dialog/MovieBuyVipDialog;", "Landroidx/fragment/app/DialogFragment;", "Landroidx/appcompat/app/AlertDialog;", "createDialog", "()Landroidx/appcompat/app/AlertDialog;", "Landroid/os/Bundle;", "savedInstanceState", "Landroid/app/Dialog;", "onCreateDialog", "(Landroid/os/Bundle;)Landroid/app/Dialog;", "Landroid/view/View;", "view", "", "onViewCreated", "(Landroid/view/View;Landroid/os/Bundle;)V", "Lcom/jbzd/media/movecartoons/view/GradientRoundCornerButton;", "btn$delegate", "Lkotlin/Lazy;", "getBtn", "()Lcom/jbzd/media/movecartoons/view/GradientRoundCornerButton;", "btn", "kotlin.jvm.PlatformType", "contentView$delegate", "getContentView", "()Landroid/view/View;", "contentView", "Landroid/widget/TextView;", "tvTip$delegate", "getTvTip", "()Landroid/widget/TextView;", "tvTip", "Lkotlin/Function0;", "submit", "Lkotlin/jvm/functions/Function0;", "getSubmit", "()Lkotlin/jvm/functions/Function0;", "", "tip", "Ljava/lang/String;", "getTip", "()Ljava/lang/String;", "alertDialog$delegate", "getAlertDialog", "alertDialog", "Landroid/widget/ImageView;", "btnClose$delegate", "getBtnClose", "()Landroid/widget/ImageView;", "btnClose", "<init>", "(Ljava/lang/String;Lkotlin/jvm/functions/Function0;)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class MovieBuyVipDialog extends DialogFragment {

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

    @NotNull
    private final Function0<Unit> submit;

    @NotNull
    private final String tip;

    /* renamed from: tvTip$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tvTip;

    /* JADX WARN: Multi-variable type inference failed */
    public MovieBuyVipDialog() {
        this(null, 0 == true ? 1 : 0, 3, 0 == true ? 1 : 0);
    }

    public /* synthetic */ MovieBuyVipDialog(String str, Function0 function0, int i2, DefaultConstructorMarker defaultConstructorMarker) {
        this((i2 & 1) != 0 ? "邀请好友，或充值VIP，观看完整版！" : str, (i2 & 2) != 0 ? new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.MovieBuyVipDialog.1
            @Override // kotlin.jvm.functions.Function0
            public /* bridge */ /* synthetic */ Unit invoke() {
                invoke2();
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2() {
            }
        } : function0);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final AlertDialog createDialog() {
        AlertDialog m624j0 = C1499a.m624j0(new AlertDialog.Builder(requireContext(), R.style.dialog_center), getContentView(), "Builder(requireContext(), R.style.dialog_center)\n            .setView(contentView)\n            .create()");
        getTvTip().setText(this.tip);
        C2354n.m2374A(getBtn(), 0L, new Function1<GradientRoundCornerButton, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.MovieBuyVipDialog$createDialog$1
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
                Intrinsics.checkNotNullParameter(it, "it");
                MovieBuyVipDialog.this.getSubmit().invoke();
                MovieBuyVipDialog.this.dismissAllowingStateLoss();
            }
        }, 1);
        C2354n.m2374A(getBtnClose(), 0L, new Function1<ImageView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.MovieBuyVipDialog$createDialog$2
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
                MovieBuyVipDialog.this.dismissAllowingStateLoss();
            }
        }, 1);
        Window window = m624j0.getWindow();
        if (window != null) {
            window.setDimAmount(0.0f);
        }
        WindowManager.LayoutParams attributes = window == null ? null : window.getAttributes();
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

    private final TextView getTvTip() {
        return (TextView) this.tvTip.getValue();
    }

    public void _$_clearFindViewByIdCache() {
    }

    @NotNull
    public final Function0<Unit> getSubmit() {
        return this.submit;
    }

    @NotNull
    public final String getTip() {
        return this.tip;
    }

    @Override // androidx.fragment.app.DialogFragment
    @NotNull
    public Dialog onCreateDialog(@Nullable Bundle savedInstanceState) {
        return getAlertDialog();
    }

    @Override // androidx.fragment.app.Fragment
    public void onViewCreated(@NotNull View view, @Nullable Bundle savedInstanceState) {
        Intrinsics.checkNotNullParameter(view, "view");
        super.onViewCreated(view, savedInstanceState);
    }

    public MovieBuyVipDialog(@NotNull String tip, @NotNull Function0<Unit> submit) {
        Intrinsics.checkNotNullParameter(tip, "tip");
        Intrinsics.checkNotNullParameter(submit, "submit");
        this.tip = tip;
        this.submit = submit;
        this.contentView = LazyKt__LazyJVMKt.lazy(new Function0<View>() { // from class: com.jbzd.media.movecartoons.ui.dialog.MovieBuyVipDialog$contentView$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            public final View invoke() {
                return LayoutInflater.from(MovieBuyVipDialog.this.getContext()).inflate(R.layout.dialog_movie_buy_vip, (ViewGroup) null);
            }
        });
        this.tvTip = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.dialog.MovieBuyVipDialog$tvTip$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final TextView invoke() {
                View contentView;
                contentView = MovieBuyVipDialog.this.getContentView();
                View findViewById = contentView.findViewById(R.id.tvTips);
                Objects.requireNonNull(findViewById, "null cannot be cast to non-null type android.widget.TextView");
                return (TextView) findViewById;
            }
        });
        this.btn = LazyKt__LazyJVMKt.lazy(new Function0<GradientRoundCornerButton>() { // from class: com.jbzd.media.movecartoons.ui.dialog.MovieBuyVipDialog$btn$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final GradientRoundCornerButton invoke() {
                View contentView;
                contentView = MovieBuyVipDialog.this.getContentView();
                View findViewById = contentView.findViewById(R.id.btn);
                Objects.requireNonNull(findViewById, "null cannot be cast to non-null type com.jbzd.media.movecartoons.view.GradientRoundCornerButton");
                return (GradientRoundCornerButton) findViewById;
            }
        });
        this.btnClose = LazyKt__LazyJVMKt.lazy(new Function0<ImageView>() { // from class: com.jbzd.media.movecartoons.ui.dialog.MovieBuyVipDialog$btnClose$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final ImageView invoke() {
                View contentView;
                contentView = MovieBuyVipDialog.this.getContentView();
                View findViewById = contentView.findViewById(R.id.btnClose);
                Objects.requireNonNull(findViewById, "null cannot be cast to non-null type android.widget.ImageView");
                return (ImageView) findViewById;
            }
        });
        this.alertDialog = LazyKt__LazyJVMKt.lazy(new Function0<AlertDialog>() { // from class: com.jbzd.media.movecartoons.ui.dialog.MovieBuyVipDialog$alertDialog$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final AlertDialog invoke() {
                AlertDialog createDialog;
                createDialog = MovieBuyVipDialog.this.createDialog();
                return createDialog;
            }
        });
    }
}
