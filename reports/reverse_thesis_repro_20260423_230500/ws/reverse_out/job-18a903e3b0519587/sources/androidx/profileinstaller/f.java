package androidx.profileinstaller;

/* JADX INFO: loaded from: classes.dex */
enum f {
    DEX_FILES(0),
    EXTRA_DESCRIPTORS(1),
    CLASSES(2),
    METHODS(3),
    AGGREGATION_COUNT(4);


    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final long f5232b;

    f(long j3) {
        this.f5232b = j3;
    }

    public long b() {
        return this.f5232b;
    }
}
