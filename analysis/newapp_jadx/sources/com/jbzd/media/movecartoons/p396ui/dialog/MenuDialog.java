package com.jbzd.media.movecartoons.p396ui.dialog;

import android.app.Dialog;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.view.WindowManager;
import android.widget.FrameLayout;
import androidx.appcompat.app.AlertDialog;
import androidx.fragment.app.DialogFragment;
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

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000<\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\u0010\u000e\n\u0002\u0018\u0002\n\u0002\b\u000e\u0018\u00002\u00020\u0001B,\u0012#\b\u0002\u0010\u0018\u001a\u001d\u0012\u0013\u0012\u00110\u0014¢\u0006\f\b\u0015\u0012\b\b\u0016\u0012\u0004\b\b(\u0017\u0012\u0004\u0012\u00020\f0\u0013¢\u0006\u0004\b!\u0010\"J\u000f\u0010\u0003\u001a\u00020\u0002H\u0002¢\u0006\u0004\b\u0003\u0010\u0004J\u0019\u0010\b\u001a\u00020\u00072\b\u0010\u0006\u001a\u0004\u0018\u00010\u0005H\u0016¢\u0006\u0004\b\b\u0010\tJ!\u0010\r\u001a\u00020\f2\u0006\u0010\u000b\u001a\u00020\n2\b\u0010\u0006\u001a\u0004\u0018\u00010\u0005H\u0016¢\u0006\u0004\b\r\u0010\u000eR\u001d\u0010\u0012\u001a\u00020\u00028B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u000f\u0010\u0010\u001a\u0004\b\u0011\u0010\u0004R4\u0010\u0018\u001a\u001d\u0012\u0013\u0012\u00110\u0014¢\u0006\f\b\u0015\u0012\b\b\u0016\u0012\u0004\b\b(\u0017\u0012\u0004\u0012\u00020\f0\u00138\u0006@\u0006¢\u0006\f\n\u0004\b\u0018\u0010\u0019\u001a\u0004\b\u001a\u0010\u001bR%\u0010 \u001a\n \u001c*\u0004\u0018\u00010\n0\n8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u001d\u0010\u0010\u001a\u0004\b\u001e\u0010\u001f¨\u0006#"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/dialog/MenuDialog;", "Landroidx/fragment/app/DialogFragment;", "Landroidx/appcompat/app/AlertDialog;", "createDialog", "()Landroidx/appcompat/app/AlertDialog;", "Landroid/os/Bundle;", "savedInstanceState", "Landroid/app/Dialog;", "onCreateDialog", "(Landroid/os/Bundle;)Landroid/app/Dialog;", "Landroid/view/View;", "view", "", "onViewCreated", "(Landroid/view/View;Landroid/os/Bundle;)V", "alertDialog$delegate", "Lkotlin/Lazy;", "getAlertDialog", "alertDialog", "Lkotlin/Function1;", "", "Lkotlin/ParameterName;", "name", "type", "submit", "Lkotlin/jvm/functions/Function1;", "getSubmit", "()Lkotlin/jvm/functions/Function1;", "kotlin.jvm.PlatformType", "contentView$delegate", "getContentView", "()Landroid/view/View;", "contentView", "<init>", "(Lkotlin/jvm/functions/Function1;)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class MenuDialog extends DialogFragment {

    /* renamed from: alertDialog$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy alertDialog;

    /* renamed from: contentView$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy contentView;

    @NotNull
    private final Function1<String, Unit> submit;

    /* JADX WARN: Multi-variable type inference failed */
    public MenuDialog() {
        this(null, 1, 0 == true ? 1 : 0);
    }

    /* JADX WARN: Multi-variable type inference failed */
    public MenuDialog(@NotNull Function1<? super String, Unit> submit) {
        Intrinsics.checkNotNullParameter(submit, "submit");
        this.submit = submit;
        this.contentView = LazyKt__LazyJVMKt.lazy(new Function0<View>() { // from class: com.jbzd.media.movecartoons.ui.dialog.MenuDialog$contentView$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            public final View invoke() {
                return LayoutInflater.from(MenuDialog.this.getContext()).inflate(R.layout.dialog_menu, (ViewGroup) null);
            }
        });
        this.alertDialog = LazyKt__LazyJVMKt.lazy(new Function0<AlertDialog>() { // from class: com.jbzd.media.movecartoons.ui.dialog.MenuDialog$alertDialog$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final AlertDialog invoke() {
                AlertDialog createDialog;
                createDialog = MenuDialog.this.createDialog();
                return createDialog;
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final AlertDialog createDialog() {
        AlertDialog m624j0 = C1499a.m624j0(new AlertDialog.Builder(requireContext(), R.style.dialog_center), getContentView(), "Builder(requireContext(), R.style.dialog_center)\n            .setView(contentView)\n            .create()");
        C2354n.m2374A(getContentView().findViewById(R.id.btnRest), 0L, new Function1<FrameLayout, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.MenuDialog$createDialog$1
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(FrameLayout frameLayout) {
                invoke2(frameLayout);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(FrameLayout frameLayout) {
                MenuDialog.this.getSubmit().invoke("rest");
                MenuDialog.this.dismissAllowingStateLoss();
            }
        }, 1);
        C2354n.m2374A(getContentView().findViewById(R.id.btnRecharge), 0L, new Function1<FrameLayout, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.MenuDialog$createDialog$2
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(FrameLayout frameLayout) {
                invoke2(frameLayout);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(FrameLayout frameLayout) {
                MenuDialog.this.getSubmit().invoke("recharge");
                MenuDialog.this.dismissAllowingStateLoss();
            }
        }, 1);
        C2354n.m2374A(getContentView().findViewById(R.id.btnExit), 0L, new Function1<FrameLayout, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.MenuDialog$createDialog$3
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(FrameLayout frameLayout) {
                invoke2(frameLayout);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(FrameLayout frameLayout) {
                MenuDialog.this.getSubmit().invoke("exit");
                MenuDialog.this.dismissAllowingStateLoss();
            }
        }, 1);
        Window window = m624j0.getWindow();
        if (window != null) {
            window.setDimAmount(0.0f);
        }
        WindowManager.LayoutParams attributes = window == null ? null : window.getAttributes();
        if (attributes != null) {
            attributes.windowAnimations = R.style.SmallSHowAnimation;
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
    public final Function1<String, Unit> getSubmit() {
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

    public /* synthetic */ MenuDialog(Function1 function1, int i2, DefaultConstructorMarker defaultConstructorMarker) {
        this((i2 & 1) != 0 ? new Function1<String, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.MenuDialog.1
            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(String str) {
                invoke2(str);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull String it) {
                Intrinsics.checkNotNullParameter(it, "it");
            }
        } : function1);
    }
}
