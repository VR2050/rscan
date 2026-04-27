package com.google.firebase.remoteconfig;

import com.google.android.gms.tasks.SuccessContinuation;
import com.google.android.gms.tasks.Task;
import com.google.firebase.remoteconfig.internal.ConfigFetchHandler;

/* JADX INFO: compiled from: com.google.firebase:firebase-config@@19.1.0 */
/* JADX INFO: loaded from: classes.dex */
final /* synthetic */ class FirebaseRemoteConfig$$Lambda$6 implements SuccessContinuation {
    private static final FirebaseRemoteConfig$$Lambda$6 instance = new FirebaseRemoteConfig$$Lambda$6();

    private FirebaseRemoteConfig$$Lambda$6() {
    }

    @Override // com.google.android.gms.tasks.SuccessContinuation
    public Task then(Object obj) {
        return FirebaseRemoteConfig.lambda$fetch$4((ConfigFetchHandler.FetchResponse) obj);
    }
}
