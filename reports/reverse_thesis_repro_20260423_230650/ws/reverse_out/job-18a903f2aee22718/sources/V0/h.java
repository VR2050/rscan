package V0;

/* JADX INFO: loaded from: classes.dex */
public class h implements d {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final int f2823a;

    public h(int i3) {
        this.f2823a = i3;
    }

    @Override // V0.d
    public c createImageTranscoder(C0.c cVar, boolean z3) {
        return new g(z3, this.f2823a);
    }
}
