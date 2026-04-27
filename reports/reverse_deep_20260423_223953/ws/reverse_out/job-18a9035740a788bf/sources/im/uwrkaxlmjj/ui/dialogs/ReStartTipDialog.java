package im.uwrkaxlmjj.ui.dialogs;

import android.view.View;
import android.widget.TextView;
import androidx.fragment.app.FragmentActivity;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: compiled from: ReStartTipDialog.kt */
/* JADX INFO: loaded from: classes5.dex */
@Metadata(bv = {1, 0, 3}, d1 = {"\u0000 \n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\u0018\u00002\u00020\u0001:\u0001\tB\u0015\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u0012\u0006\u0010\u0004\u001a\u00020\u0005¢\u0006\u0002\u0010\u0006J\b\u0010\u0007\u001a\u00020\bH\u0014R\u000e\u0010\u0002\u001a\u00020\u0003X\u0082\u0004¢\u0006\u0002\n\u0000R\u000e\u0010\u0004\u001a\u00020\u0005X\u0082\u0004¢\u0006\u0002\n\u0000¨\u0006\n"}, d2 = {"Lim/uwrkaxlmjj/ui/dialogs/ReStartTipDialog;", "Lim/uwrkaxlmjj/ui/dialogs/BaseDialog;", "activity", "Landroidx/fragment/app/FragmentActivity;", "onReStartListener", "Lim/uwrkaxlmjj/ui/dialogs/ReStartTipDialog$OnReStartListener;", "(Landroidx/fragment/app/FragmentActivity;Lim/uwrkaxlmjj/ui/dialogs/ReStartTipDialog$OnReStartListener;)V", "onStart", "", "OnReStartListener", "HMessagesPrj_prodRelease"}, k = 1, mv = {1, 1, 16})
public final class ReStartTipDialog extends BaseDialog {
    private final FragmentActivity activity;
    private final OnReStartListener onReStartListener;

    /* JADX INFO: compiled from: ReStartTipDialog.kt */
    @Metadata(bv = {1, 0, 3}, d1 = {"\u0000\u0010\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u0002\n\u0000\bf\u0018\u00002\u00020\u0001J\b\u0010\u0002\u001a\u00020\u0003H&¨\u0006\u0004"}, d2 = {"Lim/uwrkaxlmjj/ui/dialogs/ReStartTipDialog$OnReStartListener;", "", "onReStart", "", "HMessagesPrj_prodRelease"}, k = 1, mv = {1, 1, 16})
    public interface OnReStartListener {
        void onReStart();
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public ReStartTipDialog(FragmentActivity activity, OnReStartListener onReStartListener) {
        super(activity, R.layout.dialog_restart_tip);
        Intrinsics.checkParameterIsNotNull(activity, "activity");
        Intrinsics.checkParameterIsNotNull(onReStartListener, "onReStartListener");
        this.activity = activity;
        this.onReStartListener = onReStartListener;
    }

    @Override // im.uwrkaxlmjj.ui.dialogs.BaseDialog, android.app.Dialog
    protected void onStart() {
        super.onStart();
        setWidthAndHeight(0.9f, 0.0f, 17);
        setCanceledOnTouchOutside(true);
        setCancelable(false);
        TextView textView = (TextView) findViewById(R.attr.tv_cancel);
        if (textView != null) {
            textView.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.dialogs.ReStartTipDialog.onStart.1
                @Override // android.view.View.OnClickListener
                public final void onClick(View it) {
                    ReStartTipDialog.this.dismiss();
                }
            });
        }
        TextView textView2 = (TextView) findViewById(R.attr.tv_restart);
        if (textView2 != null) {
            textView2.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.dialogs.ReStartTipDialog.onStart.2
                @Override // android.view.View.OnClickListener
                public final void onClick(View it) {
                    ReStartTipDialog.this.onReStartListener.onReStart();
                }
            });
        }
    }
}
