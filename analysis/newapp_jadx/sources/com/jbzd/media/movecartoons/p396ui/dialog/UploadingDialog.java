package com.jbzd.media.movecartoons.p396ui.dialog;

import android.app.Dialog;
import android.content.DialogInterface;
import android.os.Bundle;
import android.view.KeyEvent;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ProgressBar;
import androidx.appcompat.app.AlertDialog;
import androidx.fragment.app.DialogFragment;
import com.jbzd.media.movecartoons.p396ui.dialog.UploadingDialog;
import com.qnmd.adnnm.da0yzo.R;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u00004\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\b\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0006\u0018\u0000 \u00192\u00020\u0001:\u0001\u0019B\u0007¢\u0006\u0004\b\u0017\u0010\u0018J\u0019\u0010\u0005\u001a\u00020\u00042\b\u0010\u0003\u001a\u0004\u0018\u00010\u0002H\u0016¢\u0006\u0004\b\u0005\u0010\u0006J\u0015\u0010\n\u001a\u00020\t2\u0006\u0010\b\u001a\u00020\u0007¢\u0006\u0004\b\n\u0010\u000bJ\u0015\u0010\r\u001a\u00020\t2\u0006\u0010\f\u001a\u00020\u0007¢\u0006\u0004\b\r\u0010\u000bR$\u0010\u000f\u001a\u0004\u0018\u00010\u000e8\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\u000f\u0010\u0010\u001a\u0004\b\u0011\u0010\u0012\"\u0004\b\r\u0010\u0013R\u0018\u0010\u0015\u001a\u0004\u0018\u00010\u00148\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\u0015\u0010\u0016¨\u0006\u001a"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/dialog/UploadingDialog;", "Landroidx/fragment/app/DialogFragment;", "Landroid/os/Bundle;", "savedInstanceState", "Landroid/app/Dialog;", "onCreateDialog", "(Landroid/os/Bundle;)Landroid/app/Dialog;", "", "max", "", "setMax", "(I)V", "value", "setProgress", "Landroid/widget/ProgressBar;", "progress", "Landroid/widget/ProgressBar;", "getProgress", "()Landroid/widget/ProgressBar;", "(Landroid/widget/ProgressBar;)V", "Landroid/view/View;", "contentView", "Landroid/view/View;", "<init>", "()V", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class UploadingDialog extends DialogFragment {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    @Nullable
    private View contentView;

    @Nullable
    private ProgressBar progress;

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0010\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0002\b\u0005\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0005\u0010\u0006J\r\u0010\u0003\u001a\u00020\u0002¢\u0006\u0004\b\u0003\u0010\u0004¨\u0006\u0007"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/dialog/UploadingDialog$Companion;", "", "Lcom/jbzd/media/movecartoons/ui/dialog/UploadingDialog;", "newInstance", "()Lcom/jbzd/media/movecartoons/ui/dialog/UploadingDialog;", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        @NotNull
        public final UploadingDialog newInstance() {
            return new UploadingDialog();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: onCreateDialog$lambda-1$lambda-0, reason: not valid java name */
    public static final boolean m5797onCreateDialog$lambda1$lambda0(DialogInterface dialogInterface, int i2, KeyEvent keyEvent) {
        return i2 == 4;
    }

    public void _$_clearFindViewByIdCache() {
    }

    @Nullable
    public final ProgressBar getProgress() {
        return this.progress;
    }

    @Override // androidx.fragment.app.DialogFragment
    @NotNull
    public Dialog onCreateDialog(@Nullable Bundle savedInstanceState) {
        View inflate = LayoutInflater.from(getContext()).inflate(R.layout.uploading_dialog_layout, (ViewGroup) null);
        this.contentView = inflate;
        this.progress = inflate != null ? (ProgressBar) inflate.findViewById(R.id.progress) : null;
        AlertDialog create = new AlertDialog.Builder(requireContext(), R.style.dialog_center).setCancelable(false).setView(this.contentView).create();
        Intrinsics.checkNotNullExpressionValue(create, "Builder(requireContext(), R.style.dialog_center)\n            .setCancelable(false)\n            .setView(contentView)\n            .create()");
        create.setCanceledOnTouchOutside(false);
        create.setCancelable(false);
        create.setOnKeyListener(new DialogInterface.OnKeyListener() { // from class: b.a.a.a.t.e.g0
            @Override // android.content.DialogInterface.OnKeyListener
            public final boolean onKey(DialogInterface dialogInterface, int i2, KeyEvent keyEvent) {
                boolean m5797onCreateDialog$lambda1$lambda0;
                m5797onCreateDialog$lambda1$lambda0 = UploadingDialog.m5797onCreateDialog$lambda1$lambda0(dialogInterface, i2, keyEvent);
                return m5797onCreateDialog$lambda1$lambda0;
            }
        });
        return create;
    }

    public final void setMax(int max) {
        ProgressBar progressBar = this.progress;
        if (progressBar == null) {
            return;
        }
        progressBar.setMax(max);
    }

    public final void setProgress(@Nullable ProgressBar progressBar) {
        this.progress = progressBar;
    }

    public final void setProgress(int value) {
        ProgressBar progressBar = this.progress;
        if (progressBar == null) {
            return;
        }
        progressBar.setProgress(value);
    }
}
