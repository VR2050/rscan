package com.jbzd.media.movecartoons.p396ui.dialog;

import android.app.Dialog;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.view.WindowManager;
import android.widget.ImageView;
import androidx.appcompat.app.AlertDialog;
import androidx.fragment.app.DialogFragment;
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

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u00004\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u000b\n\u0002\u0018\u0002\n\u0002\b\u0007\u0018\u00002\u00020\u0001B\u0017\u0012\u000e\b\u0002\u0010\u0019\u001a\b\u0012\u0004\u0012\u00020\f0\u0018¢\u0006\u0004\b\u001d\u0010\u001eJ\u000f\u0010\u0003\u001a\u00020\u0002H\u0002¢\u0006\u0004\b\u0003\u0010\u0004J\u0019\u0010\b\u001a\u00020\u00072\b\u0010\u0006\u001a\u0004\u0018\u00010\u0005H\u0016¢\u0006\u0004\b\b\u0010\tJ!\u0010\r\u001a\u00020\f2\u0006\u0010\u000b\u001a\u00020\n2\b\u0010\u0006\u001a\u0004\u0018\u00010\u0005H\u0016¢\u0006\u0004\b\r\u0010\u000eR%\u0010\u0014\u001a\n \u000f*\u0004\u0018\u00010\n0\n8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u0010\u0010\u0011\u001a\u0004\b\u0012\u0010\u0013R\u001d\u0010\u0017\u001a\u00020\u00028B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u0015\u0010\u0011\u001a\u0004\b\u0016\u0010\u0004R\u001f\u0010\u0019\u001a\b\u0012\u0004\u0012\u00020\f0\u00188\u0006@\u0006¢\u0006\f\n\u0004\b\u0019\u0010\u001a\u001a\u0004\b\u001b\u0010\u001c¨\u0006\u001f"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/dialog/SubmitDialog;", "Landroidx/fragment/app/DialogFragment;", "Landroidx/appcompat/app/AlertDialog;", "createDialog", "()Landroidx/appcompat/app/AlertDialog;", "Landroid/os/Bundle;", "savedInstanceState", "Landroid/app/Dialog;", "onCreateDialog", "(Landroid/os/Bundle;)Landroid/app/Dialog;", "Landroid/view/View;", "view", "", "onViewCreated", "(Landroid/view/View;Landroid/os/Bundle;)V", "kotlin.jvm.PlatformType", "contentView$delegate", "Lkotlin/Lazy;", "getContentView", "()Landroid/view/View;", "contentView", "alertDialog$delegate", "getAlertDialog", "alertDialog", "Lkotlin/Function0;", "submit", "Lkotlin/jvm/functions/Function0;", "getSubmit", "()Lkotlin/jvm/functions/Function0;", "<init>", "(Lkotlin/jvm/functions/Function0;)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class SubmitDialog extends DialogFragment {

    /* renamed from: alertDialog$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy alertDialog;

    /* renamed from: contentView$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy contentView;

    @NotNull
    private final Function0<Unit> submit;

    /* JADX WARN: Multi-variable type inference failed */
    public SubmitDialog() {
        this(null, 1, 0 == true ? 1 : 0);
    }

    public SubmitDialog(@NotNull Function0<Unit> submit) {
        Intrinsics.checkNotNullParameter(submit, "submit");
        this.submit = submit;
        this.contentView = LazyKt__LazyJVMKt.lazy(new Function0<View>() { // from class: com.jbzd.media.movecartoons.ui.dialog.SubmitDialog$contentView$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            public final View invoke() {
                return LayoutInflater.from(SubmitDialog.this.getContext()).inflate(R.layout.dialog_submit, (ViewGroup) null);
            }
        });
        this.alertDialog = LazyKt__LazyJVMKt.lazy(new Function0<AlertDialog>() { // from class: com.jbzd.media.movecartoons.ui.dialog.SubmitDialog$alertDialog$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final AlertDialog invoke() {
                AlertDialog createDialog;
                createDialog = SubmitDialog.this.createDialog();
                return createDialog;
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final AlertDialog createDialog() {
        AlertDialog m624j0 = C1499a.m624j0(new AlertDialog.Builder(requireContext(), R.style.dialog_center), getContentView(), "Builder(requireContext(), R.style.dialog_center)\n            .setView(contentView)\n            .create()");
        ImageView imageView = (ImageView) getContentView().findViewById(R.id.close);
        GradientRoundCornerButton gradientRoundCornerButton = (GradientRoundCornerButton) getContentView().findViewById(R.id.btn_submit_aichangeface_video);
        C2354n.m2374A(imageView, 0L, new Function1<ImageView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.SubmitDialog$createDialog$1
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
                SubmitDialog.this.dismissAllowingStateLoss();
            }
        }, 1);
        C2354n.m2374A(gradientRoundCornerButton, 0L, new Function1<GradientRoundCornerButton, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.SubmitDialog$createDialog$2
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(GradientRoundCornerButton gradientRoundCornerButton2) {
                invoke2(gradientRoundCornerButton2);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(GradientRoundCornerButton gradientRoundCornerButton2) {
                SubmitDialog.this.getSubmit().invoke();
                SubmitDialog.this.dismissAllowingStateLoss();
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

    private final View getContentView() {
        return (View) this.contentView.getValue();
    }

    public void _$_clearFindViewByIdCache() {
    }

    @NotNull
    public final Function0<Unit> getSubmit() {
        return this.submit;
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

    public /* synthetic */ SubmitDialog(Function0 function0, int i2, DefaultConstructorMarker defaultConstructorMarker) {
        this((i2 & 1) != 0 ? new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.SubmitDialog.1
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
}
