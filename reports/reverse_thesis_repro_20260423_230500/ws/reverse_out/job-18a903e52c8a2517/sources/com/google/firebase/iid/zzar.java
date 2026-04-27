package com.google.firebase.iid;

import android.os.Looper;
import android.os.Message;

/* JADX INFO: compiled from: com.google.firebase:firebase-iid@@20.0.2 */
/* JADX INFO: loaded from: classes.dex */
final class zzar extends com.google.android.gms.internal.firebase_messaging.zze {
    private final /* synthetic */ zzao zza;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    zzar(zzao zzaoVar, Looper looper) {
        super(looper);
        this.zza = zzaoVar;
    }

    @Override // android.os.Handler
    public final void handleMessage(Message message) {
        this.zza.zza(message);
    }
}
