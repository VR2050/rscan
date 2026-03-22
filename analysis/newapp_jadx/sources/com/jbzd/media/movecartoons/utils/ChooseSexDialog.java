package com.jbzd.media.movecartoons.utils;

import android.view.View;
import android.widget.EditText;
import com.jbzd.media.movecartoons.p396ui.dialog.StrongBottomSheetDialog;
import com.qnmd.adnnm.da0yzo.R;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import p005b.p327w.p330b.p337d.C2861e;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u001c\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0004\u0018\u00002\u00020\u00012\u00020\u0002J\u000f\u0010\u0004\u001a\u00020\u0003H\u0016¢\u0006\u0004\b\u0004\u0010\u0005J\u0017\u0010\b\u001a\u00020\u00032\u0006\u0010\u0007\u001a\u00020\u0006H\u0016¢\u0006\u0004\b\b\u0010\t¨\u0006\n"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/utils/ChooseSexDialog;", "Lcom/jbzd/media/movecartoons/ui/dialog/StrongBottomSheetDialog;", "Landroid/view/View$OnClickListener;", "", "dismiss", "()V", "Landroid/view/View;", "v", "onClick", "(Landroid/view/View;)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class ChooseSexDialog extends StrongBottomSheetDialog implements View.OnClickListener {
    @Override // androidx.appcompat.app.AppCompatDialog, android.app.Dialog, android.content.DialogInterface
    public void dismiss() {
        View currentFocus = getCurrentFocus();
        if (currentFocus instanceof EditText) {
            C2861e.m3306d(currentFocus);
        }
        super.dismiss();
    }

    @Override // android.view.View.OnClickListener
    public void onClick(@NotNull View v) {
        Intrinsics.checkNotNullParameter(v, "v");
        switch (v.getId()) {
            case R.id.tv_sex_canel /* 2131363708 */:
                onBackPressed();
                return;
            case R.id.tv_sex_female /* 2131363709 */:
                throw null;
            case R.id.tv_sex_male /* 2131363710 */:
                throw null;
            case R.id.tv_sex_private /* 2131363711 */:
                throw null;
            default:
                return;
        }
    }
}
