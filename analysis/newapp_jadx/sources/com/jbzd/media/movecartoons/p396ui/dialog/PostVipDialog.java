package com.jbzd.media.movecartoons.p396ui.dialog;

import android.app.Dialog;
import android.content.Context;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.view.WindowManager;
import android.widget.TextView;
import androidx.appcompat.app.AlertDialog;
import androidx.fragment.app.DialogFragment;
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
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000D\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\r\n\u0002\u0010\u000e\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\n\u0018\u00002\u00020\u0001B\u0011\u0012\b\b\u0002\u0010\u001e\u001a\u00020\u001d¢\u0006\u0004\b*\u0010+J\u000f\u0010\u0003\u001a\u00020\u0002H\u0002¢\u0006\u0004\b\u0003\u0010\u0004J\u0019\u0010\b\u001a\u00020\u00072\b\u0010\u0006\u001a\u0004\u0018\u00010\u0005H\u0016¢\u0006\u0004\b\b\u0010\tJ!\u0010\r\u001a\u00020\f2\u0006\u0010\u000b\u001a\u00020\n2\b\u0010\u0006\u001a\u0004\u0018\u00010\u0005H\u0016¢\u0006\u0004\b\r\u0010\u000eR\u001d\u0010\u0014\u001a\u00020\u000f8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u0010\u0010\u0011\u001a\u0004\b\u0012\u0010\u0013R%\u0010\u0019\u001a\n \u0015*\u0004\u0018\u00010\n0\n8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u0016\u0010\u0011\u001a\u0004\b\u0017\u0010\u0018R\u001d\u0010\u001c\u001a\u00020\u000f8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u001a\u0010\u0011\u001a\u0004\b\u001b\u0010\u0013R\u0019\u0010\u001e\u001a\u00020\u001d8\u0006@\u0006¢\u0006\f\n\u0004\b\u001e\u0010\u001f\u001a\u0004\b \u0010!R\u001d\u0010&\u001a\u00020\"8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b#\u0010\u0011\u001a\u0004\b$\u0010%R\u001d\u0010)\u001a\u00020\u00028B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b'\u0010\u0011\u001a\u0004\b(\u0010\u0004¨\u0006,"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/dialog/PostVipDialog;", "Landroidx/fragment/app/DialogFragment;", "Landroidx/appcompat/app/AlertDialog;", "createDialog", "()Landroidx/appcompat/app/AlertDialog;", "Landroid/os/Bundle;", "savedInstanceState", "Landroid/app/Dialog;", "onCreateDialog", "(Landroid/os/Bundle;)Landroid/app/Dialog;", "Landroid/view/View;", "view", "", "onViewCreated", "(Landroid/view/View;Landroid/os/Bundle;)V", "Lcom/jbzd/media/movecartoons/view/GradientRoundCornerButton;", "btnClose$delegate", "Lkotlin/Lazy;", "getBtnClose", "()Lcom/jbzd/media/movecartoons/view/GradientRoundCornerButton;", "btnClose", "kotlin.jvm.PlatformType", "contentView$delegate", "getContentView", "()Landroid/view/View;", "contentView", "btnBuy$delegate", "getBtnBuy", "btnBuy", "", "tip", "Ljava/lang/String;", "getTip", "()Ljava/lang/String;", "Landroid/widget/TextView;", "tvTip$delegate", "getTvTip", "()Landroid/widget/TextView;", "tvTip", "alertDialog$delegate", "getAlertDialog", "alertDialog", "<init>", "(Ljava/lang/String;)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class PostVipDialog extends DialogFragment {

    /* renamed from: alertDialog$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy alertDialog;

    /* renamed from: btnBuy$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy btnBuy;

    /* renamed from: btnClose$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy btnClose;

    /* renamed from: contentView$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy contentView;

    @NotNull
    private final String tip;

    /* renamed from: tvTip$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tvTip;

    /* JADX WARN: Multi-variable type inference failed */
    public PostVipDialog() {
        this(null, 1, 0 == true ? 1 : 0);
    }

    public PostVipDialog(@NotNull String tip) {
        Intrinsics.checkNotNullParameter(tip, "tip");
        this.tip = tip;
        this.contentView = LazyKt__LazyJVMKt.lazy(new Function0<View>() { // from class: com.jbzd.media.movecartoons.ui.dialog.PostVipDialog$contentView$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            public final View invoke() {
                return LayoutInflater.from(PostVipDialog.this.getContext()).inflate(R.layout.dialog_post_buy_vip, (ViewGroup) null);
            }
        });
        this.tvTip = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.dialog.PostVipDialog$tvTip$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final TextView invoke() {
                View contentView;
                contentView = PostVipDialog.this.getContentView();
                View findViewById = contentView.findViewById(R.id.tvTips);
                Objects.requireNonNull(findViewById, "null cannot be cast to non-null type android.widget.TextView");
                return (TextView) findViewById;
            }
        });
        this.btnBuy = LazyKt__LazyJVMKt.lazy(new Function0<GradientRoundCornerButton>() { // from class: com.jbzd.media.movecartoons.ui.dialog.PostVipDialog$btnBuy$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final GradientRoundCornerButton invoke() {
                View contentView;
                contentView = PostVipDialog.this.getContentView();
                View findViewById = contentView.findViewById(R.id.vip);
                Objects.requireNonNull(findViewById, "null cannot be cast to non-null type com.jbzd.media.movecartoons.view.GradientRoundCornerButton");
                return (GradientRoundCornerButton) findViewById;
            }
        });
        this.btnClose = LazyKt__LazyJVMKt.lazy(new Function0<GradientRoundCornerButton>() { // from class: com.jbzd.media.movecartoons.ui.dialog.PostVipDialog$btnClose$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final GradientRoundCornerButton invoke() {
                View contentView;
                contentView = PostVipDialog.this.getContentView();
                View findViewById = contentView.findViewById(R.id.close);
                Objects.requireNonNull(findViewById, "null cannot be cast to non-null type com.jbzd.media.movecartoons.view.GradientRoundCornerButton");
                return (GradientRoundCornerButton) findViewById;
            }
        });
        this.alertDialog = LazyKt__LazyJVMKt.lazy(new Function0<AlertDialog>() { // from class: com.jbzd.media.movecartoons.ui.dialog.PostVipDialog$alertDialog$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final AlertDialog invoke() {
                AlertDialog createDialog;
                createDialog = PostVipDialog.this.createDialog();
                return createDialog;
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final AlertDialog createDialog() {
        AlertDialog m624j0 = C1499a.m624j0(new AlertDialog.Builder(requireContext(), R.style.dialog_center), getContentView(), "Builder(requireContext(), R.style.dialog_center)\n            .setView(contentView)\n            .create()");
        getTvTip().setText(this.tip);
        C2354n.m2374A(getBtnBuy(), 0L, new Function1<GradientRoundCornerButton, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.PostVipDialog$createDialog$1
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
                BuyActivity.Companion companion = BuyActivity.INSTANCE;
                Context requireContext = PostVipDialog.this.requireContext();
                Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
                companion.start(requireContext);
                PostVipDialog.this.dismissAllowingStateLoss();
            }
        }, 1);
        C2354n.m2374A(getBtnClose(), 0L, new Function1<GradientRoundCornerButton, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.PostVipDialog$createDialog$2
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
                PostVipDialog.this.dismissAllowingStateLoss();
            }
        }, 1);
        Window window = m624j0.getWindow();
        if (window != null) {
            window.setDimAmount(0.8f);
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

    private final GradientRoundCornerButton getBtnBuy() {
        return (GradientRoundCornerButton) this.btnBuy.getValue();
    }

    private final GradientRoundCornerButton getBtnClose() {
        return (GradientRoundCornerButton) this.btnClose.getValue();
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

    public /* synthetic */ PostVipDialog(String str, int i2, DefaultConstructorMarker defaultConstructorMarker) {
        this((i2 & 1) != 0 ? "为净化聊天环境,规避广告和骚扰信息,您需要成为vip会员,才能给其他用户发送私信!" : str);
    }
}
