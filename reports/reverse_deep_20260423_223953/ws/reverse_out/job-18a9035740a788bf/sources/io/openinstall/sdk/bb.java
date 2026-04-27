package io.openinstall.sdk;

import android.app.Dialog;
import android.view.View;

/* JADX INFO: loaded from: classes3.dex */
class bb implements View.OnClickListener {
    final /* synthetic */ Dialog a;

    bb(Dialog dialog) {
        this.a = dialog;
    }

    @Override // android.view.View.OnClickListener
    public void onClick(View view) {
        this.a.dismiss();
    }
}
