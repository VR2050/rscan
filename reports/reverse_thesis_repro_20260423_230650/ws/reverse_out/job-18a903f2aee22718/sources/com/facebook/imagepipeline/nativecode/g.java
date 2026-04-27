package com.facebook.imagepipeline.nativecode;

/* JADX INFO: loaded from: classes.dex */
public abstract class g {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private static boolean f6080a;

    public static synchronized void a() {
        if (!f6080a) {
            Z1.a.d("native-imagetranscoder");
            f6080a = true;
        }
    }
}
