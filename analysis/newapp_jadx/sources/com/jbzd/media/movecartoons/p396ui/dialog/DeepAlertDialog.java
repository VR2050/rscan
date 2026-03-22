package com.jbzd.media.movecartoons.p396ui.dialog;

import android.app.Dialog;
import android.content.Context;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.view.WindowManager;
import androidx.appcompat.app.AlertDialog;
import androidx.fragment.app.DialogFragment;
import androidx.viewpager.widget.ViewPager;
import com.jbzd.media.movecartoons.p396ui.vip.BuyActivity;
import com.jbzd.media.movecartoons.view.text.ImageTextView;
import com.qnmd.adnnm.da0yzo.R;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u00006\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0010\u000e\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\n\u0018\u00002\u00020\u0001B\u0017\u0012\u0006\u0010\u001e\u001a\u00020\u0013\u0012\u0006\u0010\u001f\u001a\u00020\u000e¢\u0006\u0004\b \u0010!J\u000f\u0010\u0003\u001a\u00020\u0002H\u0002¢\u0006\u0004\b\u0003\u0010\u0004J\u0019\u0010\b\u001a\u00020\u00072\b\u0010\u0006\u001a\u0004\u0018\u00010\u0005H\u0016¢\u0006\u0004\b\b\u0010\tR\u001d\u0010\r\u001a\u00020\u00028B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\n\u0010\u000b\u001a\u0004\b\f\u0010\u0004R\u0019\u0010\u000f\u001a\u00020\u000e8\u0006@\u0006¢\u0006\f\n\u0004\b\u000f\u0010\u0010\u001a\u0004\b\u0011\u0010\u0012R\u0019\u0010\u0014\u001a\u00020\u00138\u0006@\u0006¢\u0006\f\n\u0004\b\u0014\u0010\u0015\u001a\u0004\b\u0016\u0010\u0017R%\u0010\u001d\u001a\n \u0019*\u0004\u0018\u00010\u00180\u00188B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u001a\u0010\u000b\u001a\u0004\b\u001b\u0010\u001c¨\u0006\""}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/dialog/DeepAlertDialog;", "Landroidx/fragment/app/DialogFragment;", "Landroidx/appcompat/app/AlertDialog;", "createDialog", "()Landroidx/appcompat/app/AlertDialog;", "Landroid/os/Bundle;", "savedInstanceState", "Landroid/app/Dialog;", "onCreateDialog", "(Landroid/os/Bundle;)Landroid/app/Dialog;", "alertDialog$delegate", "Lkotlin/Lazy;", "getAlertDialog", "alertDialog", "", "tipsContent", "Ljava/lang/String;", "getTipsContent", "()Ljava/lang/String;", "Landroidx/viewpager/widget/ViewPager;", "pager", "Landroidx/viewpager/widget/ViewPager;", "getPager", "()Landroidx/viewpager/widget/ViewPager;", "Landroid/view/View;", "kotlin.jvm.PlatformType", "contentView$delegate", "getContentView", "()Landroid/view/View;", "contentView", "pager1", "tips", "<init>", "(Landroidx/viewpager/widget/ViewPager;Ljava/lang/String;)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class DeepAlertDialog extends DialogFragment {

    /* renamed from: alertDialog$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy alertDialog;

    /* renamed from: contentView$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy contentView;

    @NotNull
    private final ViewPager pager;

    @NotNull
    private final String tipsContent;

    public DeepAlertDialog(@NotNull ViewPager pager1, @NotNull String tips) {
        Intrinsics.checkNotNullParameter(pager1, "pager1");
        Intrinsics.checkNotNullParameter(tips, "tips");
        this.pager = pager1;
        this.tipsContent = tips;
        this.contentView = LazyKt__LazyJVMKt.lazy(new Function0<View>() { // from class: com.jbzd.media.movecartoons.ui.dialog.DeepAlertDialog$contentView$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            public final View invoke() {
                return Intrinsics.areEqual(DeepAlertDialog.this.getTipsContent(), "deep") ? LayoutInflater.from(DeepAlertDialog.this.getContext()).inflate(R.layout.dialog_alert_deep, (ViewGroup) null) : (DeepAlertDialog.this.getPager().getCurrentItem() == 1 || DeepAlertDialog.this.getPager().getCurrentItem() == 2 || DeepAlertDialog.this.getPager().getCurrentItem() == 4) ? LayoutInflater.from(DeepAlertDialog.this.getContext()).inflate(R.layout.dialog_alert_dark, (ViewGroup) null) : LayoutInflater.from(DeepAlertDialog.this.getContext()).inflate(R.layout.dialog_alert_deep, (ViewGroup) null);
            }
        });
        this.alertDialog = LazyKt__LazyJVMKt.lazy(new Function0<AlertDialog>() { // from class: com.jbzd.media.movecartoons.ui.dialog.DeepAlertDialog$alertDialog$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final AlertDialog invoke() {
                AlertDialog createDialog;
                createDialog = DeepAlertDialog.this.createDialog();
                return createDialog;
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final AlertDialog createDialog() {
        AlertDialog create;
        if (Intrinsics.areEqual(this.tipsContent, "deep")) {
            create = new AlertDialog.Builder(requireContext(), R.style.TopScaleDialogStyle).setView(getContentView()).create();
            setCancelable(false);
        } else {
            create = (this.pager.getCurrentItem() == 1 || this.pager.getCurrentItem() == 2 || this.pager.getCurrentItem() == 4) ? new AlertDialog.Builder(requireContext(), R.style.dialog_center_new).setView(getContentView()).create() : new AlertDialog.Builder(requireContext(), R.style.TopScaleDialogStyle).setView(getContentView()).create();
        }
        if (!Intrinsics.areEqual(this.tipsContent, "deep")) {
            if (this.pager.getCurrentItem() == 1 || this.pager.getCurrentItem() == 4) {
                ((ImageTextView) getContentView().findViewById(R.id.itv_blur)).setText(this.tipsContent);
            }
            if (this.pager.getCurrentItem() == 1 || this.pager.getCurrentItem() == 2 || this.pager.getCurrentItem() == 4) {
                C2354n.m2374A(getContentView().findViewById(R.id.tv_leave), 0L, new Function1<View, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.DeepAlertDialog$createDialog$1
                    {
                        super(1);
                    }

                    @Override // kotlin.jvm.functions.Function1
                    public /* bridge */ /* synthetic */ Unit invoke(View view) {
                        invoke2(view);
                        return Unit.INSTANCE;
                    }

                    /* renamed from: invoke, reason: avoid collision after fix types in other method */
                    public final void invoke2(View view) {
                        DeepAlertDialog.this.dismissAllowingStateLoss();
                        DeepAlertDialog.this.getPager().setCurrentItem(0, false);
                    }
                }, 1);
                C2354n.m2374A(getContentView().findViewById(R.id.btn_buy_vip), 0L, new Function1<View, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.DeepAlertDialog$createDialog$2$1
                    {
                        super(1);
                    }

                    @Override // kotlin.jvm.functions.Function1
                    public /* bridge */ /* synthetic */ Unit invoke(View view) {
                        invoke2(view);
                        return Unit.INSTANCE;
                    }

                    /* renamed from: invoke, reason: avoid collision after fix types in other method */
                    public final void invoke2(View view) {
                        DeepAlertDialog.this.dismissAllowingStateLoss();
                        DeepAlertDialog.this.getPager().setCurrentItem(0, false);
                        BuyActivity.Companion companion = BuyActivity.INSTANCE;
                        Context requireContext = DeepAlertDialog.this.requireContext();
                        Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
                        companion.start(requireContext);
                    }
                }, 1);
            }
        }
        C2354n.m2374A(getContentView().findViewById(R.id.btnAppStore), 0L, new Function1<View, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.DeepAlertDialog$createDialog$3$1
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(View view) {
                invoke2(view);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(View view) {
                DeepAlertDialog.this.dismissAllowingStateLoss();
                DeepAlertDialog.this.getPager().setCurrentItem(0, false);
            }
        }, 1);
        C2354n.m2374A(getContentView().findViewById(R.id.btn), 0L, new Function1<View, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.DeepAlertDialog$createDialog$4
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(View view) {
                invoke2(view);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(View view) {
                Intrinsics.areEqual(DeepAlertDialog.this.getTipsContent(), "deep");
                DeepAlertDialog.this.dismissAllowingStateLoss();
            }
        }, 1);
        Window window = create.getWindow();
        if (window != null) {
            window.setDimAmount(0.8f);
        }
        WindowManager.LayoutParams attributes = window == null ? null : window.getAttributes();
        if (attributes != null) {
            attributes.windowAnimations = R.style.BottomShowAnimation;
        }
        return create;
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
    public final ViewPager getPager() {
        return this.pager;
    }

    @NotNull
    public final String getTipsContent() {
        return this.tipsContent;
    }

    @Override // androidx.fragment.app.DialogFragment
    @NotNull
    public Dialog onCreateDialog(@Nullable Bundle savedInstanceState) {
        return getAlertDialog();
    }
}
