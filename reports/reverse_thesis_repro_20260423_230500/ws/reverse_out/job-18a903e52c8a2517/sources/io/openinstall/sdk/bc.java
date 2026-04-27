package io.openinstall.sdk;

import android.app.Dialog;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.view.View;
import com.google.android.exoplayer2.C;

/* JADX INFO: loaded from: classes3.dex */
class bc implements View.OnClickListener {
    final /* synthetic */ bd a;
    final /* synthetic */ Context b;
    final /* synthetic */ Dialog c;

    bc(bd bdVar, Context context, Dialog dialog) {
        this.a = bdVar;
        this.b = context;
        this.c = dialog;
    }

    @Override // android.view.View.OnClickListener
    public void onClick(View view) {
        try {
            Intent intent = new Intent("android.intent.action.VIEW", Uri.parse(this.a.g()));
            intent.addFlags(C.ENCODING_PCM_MU_LAW);
            this.b.startActivity(intent);
        } catch (Exception e) {
        }
        this.c.dismiss();
    }
}
