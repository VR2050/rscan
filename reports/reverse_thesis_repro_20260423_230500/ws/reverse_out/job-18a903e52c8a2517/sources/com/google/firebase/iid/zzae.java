package com.google.firebase.iid;

import android.os.Bundle;

/* JADX INFO: compiled from: com.google.firebase:firebase-iid@@20.0.2 */
/* JADX INFO: loaded from: classes.dex */
final class zzae extends zzah<Void> {
    zzae(int i, int i2, Bundle bundle) {
        super(i, 2, bundle);
    }

    @Override // com.google.firebase.iid.zzah
    final boolean zza() {
        return true;
    }

    @Override // com.google.firebase.iid.zzah
    final void zza(Bundle bundle) {
        if (bundle.getBoolean("ack", false)) {
            zza((Object) null);
        } else {
            zza(new zzag(4, "Invalid response to one way request"));
        }
    }
}
