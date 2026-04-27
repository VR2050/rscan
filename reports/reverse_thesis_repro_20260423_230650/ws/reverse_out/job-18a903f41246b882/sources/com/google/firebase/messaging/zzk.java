package com.google.firebase.messaging;

import com.google.android.datatransport.Transformer;

/* JADX INFO: compiled from: com.google.firebase:firebase-messaging@@20.1.0 */
/* JADX INFO: loaded from: classes.dex */
final /* synthetic */ class zzk implements Transformer {
    static final Transformer zza = new zzk();

    private zzk() {
    }

    @Override // com.google.android.datatransport.Transformer
    public final Object apply(Object obj) {
        return ((String) obj).getBytes();
    }
}
