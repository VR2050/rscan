package com.jbzd.media.movecartoons.p396ui.dialog;

import android.app.Dialog;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.view.WindowManager;
import com.google.android.material.bottomsheet.BottomSheetDialogFragment;
import com.qnmd.adnnm.da0yzo.R;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u00006\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0005\u0018\u00002\u00020\u00012\u00020\u0002B$\u0012\u001b\b\u0002\u0010\u0013\u001a\u0015\u0012\u0004\u0012\u00020\u0003\u0012\u0004\u0012\u00020\u0005\u0018\u00010\u0011¢\u0006\u0002\b\u0012¢\u0006\u0004\b\u0015\u0010\u0016J\u0017\u0010\u0006\u001a\u00020\u00052\u0006\u0010\u0004\u001a\u00020\u0003H\u0002¢\u0006\u0004\b\u0006\u0010\u0007J\u0019\u0010\n\u001a\u00020\u00052\b\u0010\t\u001a\u0004\u0018\u00010\bH\u0016¢\u0006\u0004\b\n\u0010\u000bJ\u0019\u0010\r\u001a\u00020\f2\b\u0010\t\u001a\u0004\u0018\u00010\bH\u0016¢\u0006\u0004\b\r\u0010\u000eJ\u0017\u0010\u0010\u001a\u00020\u00052\u0006\u0010\u000f\u001a\u00020\u0003H\u0016¢\u0006\u0004\b\u0010\u0010\u0007R)\u0010\u0013\u001a\u0015\u0012\u0004\u0012\u00020\u0003\u0012\u0004\u0012\u00020\u0005\u0018\u00010\u0011¢\u0006\u0002\b\u00128\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\b\u0013\u0010\u0014¨\u0006\u0017"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/dialog/RetrieveAccountDialog;", "Lcom/google/android/material/bottomsheet/BottomSheetDialogFragment;", "Landroid/view/View$OnClickListener;", "Landroid/view/View;", "contentView", "", "initContentView", "(Landroid/view/View;)V", "Landroid/os/Bundle;", "savedInstanceState", "onCreate", "(Landroid/os/Bundle;)V", "Landroid/app/Dialog;", "onCreateDialog", "(Landroid/os/Bundle;)Landroid/app/Dialog;", "v", "onClick", "Lkotlin/Function1;", "Lkotlin/ExtensionFunctionType;", "callback", "Lkotlin/jvm/functions/Function1;", "<init>", "(Lkotlin/jvm/functions/Function1;)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class RetrieveAccountDialog extends BottomSheetDialogFragment implements View.OnClickListener {

    @Nullable
    private final Function1<View, Unit> callback;

    /* JADX WARN: Multi-variable type inference failed */
    public RetrieveAccountDialog() {
        this(null, 1, 0 == true ? 1 : 0);
    }

    public /* synthetic */ RetrieveAccountDialog(Function1 function1, int i2, DefaultConstructorMarker defaultConstructorMarker) {
        this((i2 & 1) != 0 ? null : function1);
    }

    private final void initContentView(View contentView) {
        contentView.findViewById(R.id.btn_cancel).setOnClickListener(this);
        contentView.findViewById(R.id.txt_upload).setOnClickListener(this);
        contentView.findViewById(R.id.txt_scan).setOnClickListener(this);
    }

    public void _$_clearFindViewByIdCache() {
    }

    @Override // android.view.View.OnClickListener
    public void onClick(@NotNull View v) {
        Function1<View, Unit> function1;
        Intrinsics.checkNotNullParameter(v, "v");
        if ((v.getId() == R.id.txt_upload || v.getId() == R.id.txt_scan) && (function1 = this.callback) != null) {
            function1.invoke(v);
        }
        dismissAllowingStateLoss();
    }

    @Override // androidx.fragment.app.DialogFragment, androidx.fragment.app.Fragment
    public void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setStyle(0, R.style.dialog_center);
    }

    @Override // com.google.android.material.bottomsheet.BottomSheetDialogFragment, androidx.appcompat.app.AppCompatDialogFragment, androidx.fragment.app.DialogFragment
    @NotNull
    public Dialog onCreateDialog(@Nullable Bundle savedInstanceState) {
        Dialog onCreateDialog = super.onCreateDialog(savedInstanceState);
        Intrinsics.checkNotNullExpressionValue(onCreateDialog, "super.onCreateDialog(savedInstanceState)");
        View contentView = LayoutInflater.from(getContext()).inflate(R.layout.dialog_retrieve_layout, (ViewGroup) null);
        onCreateDialog.setContentView(contentView);
        Intrinsics.checkNotNullExpressionValue(contentView, "contentView");
        initContentView(contentView);
        Window window = onCreateDialog.getWindow();
        WindowManager.LayoutParams attributes = window != null ? window.getAttributes() : null;
        if (attributes != null) {
            attributes.windowAnimations = R.style.BottomShowAnimation;
        }
        return onCreateDialog;
    }

    /* JADX WARN: Multi-variable type inference failed */
    public RetrieveAccountDialog(@Nullable Function1<? super View, Unit> function1) {
        this.callback = function1;
    }
}
