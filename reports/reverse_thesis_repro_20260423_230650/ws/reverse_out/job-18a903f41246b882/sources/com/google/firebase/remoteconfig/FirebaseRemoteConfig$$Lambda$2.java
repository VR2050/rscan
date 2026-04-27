package com.google.firebase.remoteconfig;

import com.google.android.gms.tasks.Continuation;
import com.google.android.gms.tasks.Task;

/* JADX INFO: compiled from: com.google.firebase:firebase-config@@19.1.0 */
/* JADX INFO: loaded from: classes.dex */
final /* synthetic */ class FirebaseRemoteConfig$$Lambda$2 implements Continuation {
    private final Task arg$1;

    private FirebaseRemoteConfig$$Lambda$2(Task task) {
        this.arg$1 = task;
    }

    public static Continuation lambdaFactory$(Task task) {
        return new FirebaseRemoteConfig$$Lambda$2(task);
    }

    @Override // com.google.android.gms.tasks.Continuation
    public Object then(Task task) {
        return FirebaseRemoteConfig.lambda$ensureInitialized$0(this.arg$1, task);
    }
}
