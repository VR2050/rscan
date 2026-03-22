package com.jbzd.media.movecartoons.p396ui.dialog;

import android.app.Dialog;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.appcompat.app.AlertDialog;
import androidx.fragment.app.DialogFragment;
import com.jbzd.media.movecartoons.p396ui.index.home.child.VideoListActivity;
import com.jbzd.media.movecartoons.view.GradientRoundCornerButton;
import com.qnmd.adnnm.da0yzo.R;
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

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000B\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\b\n\u0002\b\u0004\n\u0002\u0010\u000e\n\u0002\b\n\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\r\u0018\u00002\u00020\u0001BW\u0012\b\b\u0002\u0010\u0010\u001a\u00020\u000f\u0012\u0006\u0010\u000b\u001a\u00020\n\u0012\b\b\u0002\u0010*\u001a\u00020\n\u0012\b\b\u0002\u0010(\u001a\u00020\u000f\u0012\b\b\u0002\u0010\u0018\u001a\u00020\u000f\u0012\u000e\b\u0002\u0010\"\u001a\b\u0012\u0004\u0012\u00020!0 \u0012\u000e\b\u0002\u0010&\u001a\b\u0012\u0004\u0012\u00020!0 ¢\u0006\u0004\b,\u0010-J\u000f\u0010\u0003\u001a\u00020\u0002H\u0002¢\u0006\u0004\b\u0003\u0010\u0004J\u0019\u0010\b\u001a\u00020\u00072\b\u0010\u0006\u001a\u0004\u0018\u00010\u0005H\u0016¢\u0006\u0004\b\b\u0010\tR\u0019\u0010\u000b\u001a\u00020\n8\u0006@\u0006¢\u0006\f\n\u0004\b\u000b\u0010\f\u001a\u0004\b\r\u0010\u000eR\u0019\u0010\u0010\u001a\u00020\u000f8\u0006@\u0006¢\u0006\f\n\u0004\b\u0010\u0010\u0011\u001a\u0004\b\u0012\u0010\u0013R\u001d\u0010\u0017\u001a\u00020\u00028B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u0014\u0010\u0015\u001a\u0004\b\u0016\u0010\u0004R\u0019\u0010\u0018\u001a\u00020\u000f8\u0006@\u0006¢\u0006\f\n\u0004\b\u0018\u0010\u0011\u001a\u0004\b\u0019\u0010\u0013R%\u0010\u001f\u001a\n \u001b*\u0004\u0018\u00010\u001a0\u001a8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u001c\u0010\u0015\u001a\u0004\b\u001d\u0010\u001eR\u001f\u0010\"\u001a\b\u0012\u0004\u0012\u00020!0 8\u0006@\u0006¢\u0006\f\n\u0004\b\"\u0010#\u001a\u0004\b$\u0010%R\u001f\u0010&\u001a\b\u0012\u0004\u0012\u00020!0 8\u0006@\u0006¢\u0006\f\n\u0004\b&\u0010#\u001a\u0004\b'\u0010%R\u0019\u0010(\u001a\u00020\u000f8\u0006@\u0006¢\u0006\f\n\u0004\b(\u0010\u0011\u001a\u0004\b)\u0010\u0013R\u0019\u0010*\u001a\u00020\n8\u0006@\u0006¢\u0006\f\n\u0004\b*\u0010\f\u001a\u0004\b+\u0010\u000e¨\u0006."}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/dialog/RestrictedDialog;", "Landroidx/fragment/app/DialogFragment;", "Landroidx/appcompat/app/AlertDialog;", "createDialog", "()Landroidx/appcompat/app/AlertDialog;", "Landroid/os/Bundle;", "savedInstanceState", "Landroid/app/Dialog;", "onCreateDialog", "(Landroid/os/Bundle;)Landroid/app/Dialog;", "", "watchLimit", "I", "getWatchLimit", "()I", "", VideoListActivity.KEY_TITLE, "Ljava/lang/String;", "getTitle", "()Ljava/lang/String;", "alertDialog$delegate", "Lkotlin/Lazy;", "getAlertDialog", "alertDialog", "rechargeText", "getRechargeText", "Landroid/view/View;", "kotlin.jvm.PlatformType", "contentView$delegate", "getContentView", "()Landroid/view/View;", "contentView", "Lkotlin/Function0;", "", "buyVip", "Lkotlin/jvm/functions/Function0;", "getBuyVip", "()Lkotlin/jvm/functions/Function0;", "recharge", "getRecharge", "vipText", "getVipText", "contentGravity", "getContentGravity", "<init>", "(Ljava/lang/String;IILjava/lang/String;Ljava/lang/String;Lkotlin/jvm/functions/Function0;Lkotlin/jvm/functions/Function0;)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class RestrictedDialog extends DialogFragment {

    /* renamed from: alertDialog$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy alertDialog;

    @NotNull
    private final Function0<Unit> buyVip;
    private final int contentGravity;

    /* renamed from: contentView$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy contentView;

    @NotNull
    private final Function0<Unit> recharge;

    @NotNull
    private final String rechargeText;

    @NotNull
    private final String title;

    @NotNull
    private final String vipText;
    private final int watchLimit;

    public /* synthetic */ RestrictedDialog(String str, int i2, int i3, String str2, String str3, Function0 function0, Function0 function02, int i4, DefaultConstructorMarker defaultConstructorMarker) {
        this((i4 & 1) != 0 ? "注意" : str, i2, (i4 & 4) != 0 ? 17 : i3, (i4 & 8) != 0 ? "购买VIP" : str2, (i4 & 16) != 0 ? "充值金币" : str3, (i4 & 32) != 0 ? new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.RestrictedDialog.1
            @Override // kotlin.jvm.functions.Function0
            public /* bridge */ /* synthetic */ Unit invoke() {
                invoke2();
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2() {
            }
        } : function0, (i4 & 64) != 0 ? new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.RestrictedDialog.2
            @Override // kotlin.jvm.functions.Function0
            public /* bridge */ /* synthetic */ Unit invoke() {
                invoke2();
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2() {
            }
        } : function02);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final AlertDialog createDialog() {
        AlertDialog m624j0 = C1499a.m624j0(new AlertDialog.Builder(requireContext(), R.style.dialog_center), getContentView(), "Builder(requireContext(), R.style.dialog_center)\n            .setView(contentView)\n            .create()");
        ImageView imageView = (ImageView) getContentView().findViewById(R.id.iv_close);
        TextView textView = (TextView) getContentView().findViewById(R.id.tv_title);
        TextView textView2 = (TextView) getContentView().findViewById(R.id.tv_content);
        textView2.setGravity(getContentGravity());
        GradientRoundCornerButton gradientRoundCornerButton = (GradientRoundCornerButton) getContentView().findViewById(R.id.btn_buy_vip);
        GradientRoundCornerButton gradientRoundCornerButton2 = (GradientRoundCornerButton) getContentView().findViewById(R.id.btn_recharge);
        textView.setText(this.title);
        textView2.setText("稀缺资源，您需要在本平台至少充值" + this.watchLimit + "元，才允许进入此专属区域");
        gradientRoundCornerButton.setText(this.vipText);
        gradientRoundCornerButton2.setText(this.rechargeText);
        C2354n.m2374A(imageView, 0L, new Function1<ImageView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.RestrictedDialog$createDialog$1
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(ImageView imageView2) {
                invoke2(imageView2);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(ImageView imageView2) {
                RestrictedDialog.this.dismissAllowingStateLoss();
            }
        }, 1);
        C2354n.m2374A(gradientRoundCornerButton, 0L, new Function1<GradientRoundCornerButton, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.RestrictedDialog$createDialog$2
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(GradientRoundCornerButton gradientRoundCornerButton3) {
                invoke2(gradientRoundCornerButton3);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(GradientRoundCornerButton gradientRoundCornerButton3) {
                RestrictedDialog.this.getBuyVip().invoke();
            }
        }, 1);
        C2354n.m2374A(gradientRoundCornerButton2, 0L, new Function1<GradientRoundCornerButton, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.RestrictedDialog$createDialog$3
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(GradientRoundCornerButton gradientRoundCornerButton3) {
                invoke2(gradientRoundCornerButton3);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(GradientRoundCornerButton gradientRoundCornerButton3) {
                RestrictedDialog.this.getRecharge().invoke();
            }
        }, 1);
        m624j0.setCancelable(false);
        m624j0.setCanceledOnTouchOutside(false);
        setCancelable(false);
        return m624j0;
    }

    private final AlertDialog getAlertDialog() {
        return (AlertDialog) this.alertDialog.getValue();
    }

    private final View getContentView() {
        return (View) this.contentView.getValue();
    }

    public void _$_clearFindViewByIdCache() {
    }

    @NotNull
    public final Function0<Unit> getBuyVip() {
        return this.buyVip;
    }

    public final int getContentGravity() {
        return this.contentGravity;
    }

    @NotNull
    public final Function0<Unit> getRecharge() {
        return this.recharge;
    }

    @NotNull
    public final String getRechargeText() {
        return this.rechargeText;
    }

    @NotNull
    public final String getTitle() {
        return this.title;
    }

    @NotNull
    public final String getVipText() {
        return this.vipText;
    }

    public final int getWatchLimit() {
        return this.watchLimit;
    }

    @Override // androidx.fragment.app.DialogFragment
    @NotNull
    public Dialog onCreateDialog(@Nullable Bundle savedInstanceState) {
        return getAlertDialog();
    }

    public RestrictedDialog(@NotNull String title, int i2, int i3, @NotNull String vipText, @NotNull String rechargeText, @NotNull Function0<Unit> buyVip, @NotNull Function0<Unit> recharge) {
        Intrinsics.checkNotNullParameter(title, "title");
        Intrinsics.checkNotNullParameter(vipText, "vipText");
        Intrinsics.checkNotNullParameter(rechargeText, "rechargeText");
        Intrinsics.checkNotNullParameter(buyVip, "buyVip");
        Intrinsics.checkNotNullParameter(recharge, "recharge");
        this.title = title;
        this.watchLimit = i2;
        this.contentGravity = i3;
        this.vipText = vipText;
        this.rechargeText = rechargeText;
        this.buyVip = buyVip;
        this.recharge = recharge;
        this.contentView = LazyKt__LazyJVMKt.lazy(new Function0<View>() { // from class: com.jbzd.media.movecartoons.ui.dialog.RestrictedDialog$contentView$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            public final View invoke() {
                return LayoutInflater.from(RestrictedDialog.this.getContext()).inflate(R.layout.dialog_restricted, (ViewGroup) null);
            }
        });
        this.alertDialog = LazyKt__LazyJVMKt.lazy(new Function0<AlertDialog>() { // from class: com.jbzd.media.movecartoons.ui.dialog.RestrictedDialog$alertDialog$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final AlertDialog invoke() {
                AlertDialog createDialog;
                createDialog = RestrictedDialog.this.createDialog();
                return createDialog;
            }
        });
    }
}
