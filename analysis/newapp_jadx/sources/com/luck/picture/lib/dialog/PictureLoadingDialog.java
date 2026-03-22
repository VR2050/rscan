package com.luck.picture.lib.dialog;

import android.app.Dialog;
import android.content.Context;
import android.os.Bundle;
import android.view.Window;
import com.luck.picture.lib.C3979R;

/* loaded from: classes2.dex */
public class PictureLoadingDialog extends Dialog {
    public PictureLoadingDialog(Context context) {
        super(context, C3979R.style.Picture_Theme_AlertDialog);
        setCancelable(true);
        setCanceledOnTouchOutside(false);
        Window window = getWindow();
        if (window != null) {
            window.setWindowAnimations(C3979R.style.PictureThemeDialogWindowStyle);
        }
    }

    @Override // android.app.Dialog
    public void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        setContentView(C3979R.layout.picture_alert_dialog);
    }
}
