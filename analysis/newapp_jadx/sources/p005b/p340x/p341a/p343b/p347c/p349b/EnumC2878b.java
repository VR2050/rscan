package p005b.p340x.p341a.p343b.p347c.p349b;

/* renamed from: b.x.a.b.c.b.b */
/* loaded from: classes2.dex */
public enum EnumC2878b {
    None(0, false, false, false, false, false),
    PullDownToRefresh(1, true, false, false, false, false),
    PullUpToLoad(2, true, false, false, false, false),
    PullDownCanceled(1, false, false, false, false, false),
    PullUpCanceled(2, false, false, false, false, false),
    ReleaseToRefresh(1, true, false, false, false, true),
    ReleaseToLoad(2, true, false, false, false, true),
    ReleaseToTwoLevel(1, true, false, false, true, true),
    TwoLevelReleased(1, false, false, false, true, false),
    RefreshReleased(1, false, false, false, false, false),
    LoadReleased(2, false, false, false, false, false),
    Refreshing(1, false, true, false, false, false),
    Loading(2, false, true, false, false, false),
    TwoLevel(1, false, true, false, true, false),
    RefreshFinish(1, false, false, true, false, false),
    LoadFinish(2, false, false, true, false, false),
    TwoLevelFinish(1, false, false, true, true, false);


    /* renamed from: A */
    public final boolean f7880A;

    /* renamed from: B */
    public final boolean f7881B;

    /* renamed from: v */
    public final boolean f7882v;

    /* renamed from: w */
    public final boolean f7883w;

    /* renamed from: x */
    public final boolean f7884x;

    /* renamed from: y */
    public final boolean f7885y;

    /* renamed from: z */
    public final boolean f7886z;

    EnumC2878b(int i2, boolean z, boolean z2, boolean z3, boolean z4, boolean z5) {
        this.f7882v = i2 == 1;
        this.f7883w = i2 == 2;
        this.f7885y = z;
        this.f7886z = z2;
        this.f7880A = z3;
        this.f7884x = z4;
        this.f7881B = z5;
    }

    /* renamed from: a */
    public EnumC2878b m3324a() {
        return (!this.f7882v || this.f7884x) ? this : values()[ordinal() + 1];
    }

    /* renamed from: b */
    public EnumC2878b m3325b() {
        return (!this.f7883w || this.f7884x) ? this : values()[ordinal() - 1];
    }
}
