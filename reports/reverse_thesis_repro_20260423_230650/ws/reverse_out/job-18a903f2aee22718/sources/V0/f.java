package V0;

import I0.z;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public final class f implements d {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final int f2814a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final boolean f2815b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final d f2816c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final Integer f2817d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final boolean f2818e;

    public f(int i3, boolean z3, d dVar, Integer num, boolean z4) {
        this.f2814a = i3;
        this.f2815b = z3;
        this.f2816c = dVar;
        this.f2817d = num;
        this.f2818e = z4;
    }

    private final c a(C0.c cVar, boolean z3) {
        d dVar = this.f2816c;
        if (dVar != null) {
            return dVar.createImageTranscoder(cVar, z3);
        }
        return null;
    }

    private final c b(C0.c cVar, boolean z3) {
        Integer num = this.f2817d;
        if (num == null) {
            return null;
        }
        if (num != null && num.intValue() == 0) {
            return c(cVar, z3);
        }
        if (num == null || num.intValue() != 1) {
            throw new IllegalArgumentException("Invalid ImageTranscoderType");
        }
        return d(cVar, z3);
    }

    private final c c(C0.c cVar, boolean z3) {
        return com.facebook.imagepipeline.nativecode.f.a(this.f2814a, this.f2815b, this.f2818e).createImageTranscoder(cVar, z3);
    }

    private final c d(C0.c cVar, boolean z3) {
        c cVarCreateImageTranscoder = new h(this.f2814a).createImageTranscoder(cVar, z3);
        j.e(cVarCreateImageTranscoder, "createImageTranscoder(...)");
        return cVarCreateImageTranscoder;
    }

    @Override // V0.d
    public c createImageTranscoder(C0.c cVar, boolean z3) {
        j.f(cVar, "imageFormat");
        c cVarA = a(cVar, z3);
        if (cVarA == null) {
            cVarA = b(cVar, z3);
        }
        if (cVarA == null && z.a()) {
            cVarA = c(cVar, z3);
        }
        return cVarA == null ? d(cVar, z3) : cVarA;
    }
}
