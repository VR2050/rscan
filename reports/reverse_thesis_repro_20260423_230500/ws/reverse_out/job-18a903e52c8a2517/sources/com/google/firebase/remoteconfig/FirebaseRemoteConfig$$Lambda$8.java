package com.google.firebase.remoteconfig;

import java.util.concurrent.Callable;

/* JADX INFO: compiled from: com.google.firebase:firebase-config@@19.1.0 */
/* JADX INFO: loaded from: classes.dex */
final /* synthetic */ class FirebaseRemoteConfig$$Lambda$8 implements Callable {
    private final FirebaseRemoteConfig arg$1;
    private final FirebaseRemoteConfigSettings arg$2;

    private FirebaseRemoteConfig$$Lambda$8(FirebaseRemoteConfig firebaseRemoteConfig, FirebaseRemoteConfigSettings firebaseRemoteConfigSettings) {
        this.arg$1 = firebaseRemoteConfig;
        this.arg$2 = firebaseRemoteConfigSettings;
    }

    public static Callable lambdaFactory$(FirebaseRemoteConfig firebaseRemoteConfig, FirebaseRemoteConfigSettings firebaseRemoteConfigSettings) {
        return new FirebaseRemoteConfig$$Lambda$8(firebaseRemoteConfig, firebaseRemoteConfigSettings);
    }

    @Override // java.util.concurrent.Callable
    public Object call() {
        return FirebaseRemoteConfig.lambda$setConfigSettingsAsync$6(this.arg$1, this.arg$2);
    }
}
