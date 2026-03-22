package p005b.p340x.p354b.p355a.p357c;

/* renamed from: b.x.b.a.c.b */
/* loaded from: classes2.dex */
public enum EnumC2903b {
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
    public final boolean f7946A;

    /* renamed from: B */
    public final boolean f7947B;

    /* renamed from: v */
    public final boolean f7948v;

    /* renamed from: w */
    public final boolean f7949w;

    /* renamed from: x */
    public final boolean f7950x;

    /* renamed from: y */
    public final boolean f7951y;

    /* renamed from: z */
    public final boolean f7952z;

    EnumC2903b(int i2, boolean z, boolean z2, boolean z3, boolean z4, boolean z5) {
        this.f7948v = i2 == 1;
        this.f7949w = i2 == 2;
        this.f7951y = z;
        this.f7952z = z2;
        this.f7946A = z3;
        this.f7950x = z4;
        this.f7947B = z5;
    }

    /* renamed from: a */
    public EnumC2903b m3359a() {
        return (!this.f7948v || this.f7950x) ? this : values()[ordinal() + 1];
    }

    /* renamed from: b */
    public EnumC2903b m3360b() {
        return (!this.f7949w || this.f7950x) ? this : values()[ordinal() - 1];
    }
}
