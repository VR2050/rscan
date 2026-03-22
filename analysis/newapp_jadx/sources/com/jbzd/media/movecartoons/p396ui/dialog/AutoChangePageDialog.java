package com.jbzd.media.movecartoons.p396ui.dialog;

import android.app.Dialog;
import android.os.Bundle;
import android.text.Html;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.view.WindowManager;
import android.widget.SeekBar;
import android.widget.TextView;
import androidx.core.app.NotificationCompat;
import com.google.android.material.bottomsheet.BottomSheetDialogFragment;
import com.qnmd.adnnm.da0yzo.R;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000R\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\u0010\b\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u000b\n\u0002\b\t\n\u0002\u0010\t\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\t\u0018\u00002\u00020\u00012\u00020\u0002BG\u0012\u0006\u0010\u0015\u001a\u00020 \u00126\u0010\u0018\u001a2\u0012\u0013\u0012\u00110\u0012¢\u0006\f\b\u0013\u0012\b\b\u0014\u0012\u0004\b\b(\u0015\u0012\u0013\u0012\u00110\u0016¢\u0006\f\b\u0013\u0012\b\b\u0014\u0012\u0004\b\b(\u0017\u0012\u0004\u0012\u00020\u00050\u0011¢\u0006\u0004\b+\u0010,J\u0017\u0010\u0006\u001a\u00020\u00052\u0006\u0010\u0004\u001a\u00020\u0003H\u0002¢\u0006\u0004\b\u0006\u0010\u0007J\u0019\u0010\n\u001a\u00020\u00052\b\u0010\t\u001a\u0004\u0018\u00010\bH\u0016¢\u0006\u0004\b\n\u0010\u000bJ\u0019\u0010\r\u001a\u00020\f2\b\u0010\t\u001a\u0004\u0018\u00010\bH\u0016¢\u0006\u0004\b\r\u0010\u000eJ\u0017\u0010\u0010\u001a\u00020\u00052\u0006\u0010\u000f\u001a\u00020\u0003H\u0016¢\u0006\u0004\b\u0010\u0010\u0007RF\u0010\u0018\u001a2\u0012\u0013\u0012\u00110\u0012¢\u0006\f\b\u0013\u0012\b\b\u0014\u0012\u0004\b\b(\u0015\u0012\u0013\u0012\u00110\u0016¢\u0006\f\b\u0013\u0012\b\b\u0014\u0012\u0004\b\b(\u0017\u0012\u0004\u0012\u00020\u00050\u00118\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\b\u0018\u0010\u0019R\"\u0010\u001a\u001a\u00020\u00128\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\u001a\u0010\u001b\u001a\u0004\b\u001c\u0010\u001d\"\u0004\b\u001e\u0010\u001fR\u0019\u0010\u0015\u001a\u00020 8\u0006@\u0006¢\u0006\f\n\u0004\b\u0015\u0010!\u001a\u0004\b\"\u0010#R\"\u0010%\u001a\u00020$8\u0006@\u0006X\u0086.¢\u0006\u0012\n\u0004\b%\u0010&\u001a\u0004\b'\u0010(\"\u0004\b)\u0010*¨\u0006-"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/dialog/AutoChangePageDialog;", "Lcom/google/android/material/bottomsheet/BottomSheetDialogFragment;", "Landroid/view/View$OnClickListener;", "Landroid/view/View;", "contentView", "", "initContentView", "(Landroid/view/View;)V", "Landroid/os/Bundle;", "savedInstanceState", "onCreate", "(Landroid/os/Bundle;)V", "Landroid/app/Dialog;", "onCreateDialog", "(Landroid/os/Bundle;)Landroid/app/Dialog;", "view", "onClick", "Lkotlin/Function2;", "", "Lkotlin/ParameterName;", "name", "speed", "", NotificationCompat.CATEGORY_STATUS, "callback", "Lkotlin/jvm/functions/Function2;", "showProgress", "I", "getShowProgress", "()I", "setShowProgress", "(I)V", "", "J", "getSpeed", "()J", "Landroid/widget/SeekBar;", "seekpar_auto_page", "Landroid/widget/SeekBar;", "getSeekpar_auto_page", "()Landroid/widget/SeekBar;", "setSeekpar_auto_page", "(Landroid/widget/SeekBar;)V", "<init>", "(JLkotlin/jvm/functions/Function2;)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class AutoChangePageDialog extends BottomSheetDialogFragment implements View.OnClickListener {

    @NotNull
    private final Function2<Integer, Boolean, Unit> callback;
    public SeekBar seekpar_auto_page;
    private int showProgress;
    private final long speed;

    /* JADX WARN: Multi-variable type inference failed */
    public AutoChangePageDialog(long j2, @NotNull Function2<? super Integer, ? super Boolean, Unit> callback) {
        Intrinsics.checkNotNullParameter(callback, "callback");
        this.speed = j2;
        this.callback = callback;
    }

    private final void initContentView(final View contentView) {
        View findViewById = contentView.findViewById(R.id.seekpar_auto_page);
        Intrinsics.checkNotNullExpressionValue(findViewById, "contentView.findViewById<SeekBar>(R.id.seekpar_auto_page)");
        setSeekpar_auto_page((SeekBar) findViewById);
        contentView.findViewById(R.id.tv_auto_page_end).setOnClickListener(this);
        contentView.findViewById(R.id.tv_auto_page_start).setOnClickListener(this);
        this.showProgress = (int) this.speed;
        getSeekpar_auto_page().setProgress(this.showProgress);
        StringBuilder sb = new StringBuilder();
        sb.append("自动翻页间隔 <b><font color= '#ffe200'>");
        ((TextView) contentView.findViewById(R.id.tv_autopage_title)).setText(Html.fromHtml(C1499a.m580B(sb, this.showProgress, "</font></b> 秒")));
        getSeekpar_auto_page().setOnSeekBarChangeListener(new SeekBar.OnSeekBarChangeListener() { // from class: com.jbzd.media.movecartoons.ui.dialog.AutoChangePageDialog$initContentView$1
            @Override // android.widget.SeekBar.OnSeekBarChangeListener
            public void onProgressChanged(@NotNull SeekBar seekBar, int progress, boolean fromUser) {
                Intrinsics.checkNotNullParameter(seekBar, "seekBar");
                AutoChangePageDialog.this.setShowProgress(progress);
                ((TextView) contentView.findViewById(R.id.tv_autopage_title)).setText(Html.fromHtml("自动翻页间隔 <b><font color= '#ffe200'> " + AutoChangePageDialog.this.getShowProgress() + " </font></b> 秒"));
            }

            @Override // android.widget.SeekBar.OnSeekBarChangeListener
            public void onStartTrackingTouch(@NotNull SeekBar seekBar) {
                Intrinsics.checkNotNullParameter(seekBar, "seekBar");
            }

            @Override // android.widget.SeekBar.OnSeekBarChangeListener
            public void onStopTrackingTouch(@NotNull SeekBar seekBar) {
                Intrinsics.checkNotNullParameter(seekBar, "seekBar");
            }
        });
    }

    public void _$_clearFindViewByIdCache() {
    }

    @NotNull
    public final SeekBar getSeekpar_auto_page() {
        SeekBar seekBar = this.seekpar_auto_page;
        if (seekBar != null) {
            return seekBar;
        }
        Intrinsics.throwUninitializedPropertyAccessException("seekpar_auto_page");
        throw null;
    }

    public final int getShowProgress() {
        return this.showProgress;
    }

    public final long getSpeed() {
        return this.speed;
    }

    @Override // android.view.View.OnClickListener
    public void onClick(@NotNull View view) {
        Intrinsics.checkNotNullParameter(view, "view");
        if (view.getId() == R.id.tv_auto_page_end) {
            this.callback.invoke(Integer.valueOf(this.showProgress), Boolean.FALSE);
        } else if (view.getId() == R.id.tv_auto_page_start) {
            this.callback.invoke(Integer.valueOf(this.showProgress), Boolean.TRUE);
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
        View contentView = LayoutInflater.from(getContext()).inflate(R.layout.dialog_auto_page, (ViewGroup) null);
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

    public final void setSeekpar_auto_page(@NotNull SeekBar seekBar) {
        Intrinsics.checkNotNullParameter(seekBar, "<set-?>");
        this.seekpar_auto_page = seekBar;
    }

    public final void setShowProgress(int i2) {
        this.showProgress = i2;
    }
}
