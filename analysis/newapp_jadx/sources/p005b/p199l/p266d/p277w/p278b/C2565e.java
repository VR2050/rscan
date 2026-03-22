package p005b.p199l.p266d.p277w.p278b;

import com.alibaba.fastjson.asm.Opcodes;
import com.google.android.material.behavior.HideBottomViewOnScrollBehavior;
import tv.danmaku.ijk.media.player.IjkMediaMeta;

/* renamed from: b.l.d.w.b.e */
/* loaded from: classes2.dex */
public final class C2565e {

    /* renamed from: a */
    public static final C2565e[] f6998a = {new C2565e(1, 10, 10, 8, 8, new c(5, new b(1, 3, null), null)), new C2565e(2, 12, 12, 10, 10, new c(7, new b(1, 5, null), null)), new C2565e(3, 14, 14, 12, 12, new c(10, new b(1, 8, null), null)), new C2565e(4, 16, 16, 14, 14, new c(12, new b(1, 12, null), null)), new C2565e(5, 18, 18, 16, 16, new c(14, new b(1, 18, null), null)), new C2565e(6, 20, 20, 18, 18, new c(18, new b(1, 22, null), null)), new C2565e(7, 22, 22, 20, 20, new c(20, new b(1, 30, null), null)), new C2565e(8, 24, 24, 22, 22, new c(24, new b(1, 36, null), null)), new C2565e(9, 26, 26, 24, 24, new c(28, new b(1, 44, null), null)), new C2565e(10, 32, 32, 14, 14, new c(36, new b(1, 62, null), null)), new C2565e(11, 36, 36, 16, 16, new c(42, new b(1, 86, null), null)), new C2565e(12, 40, 40, 18, 18, new c(48, new b(1, 114, null), null)), new C2565e(13, 44, 44, 20, 20, new c(56, new b(1, IjkMediaMeta.FF_PROFILE_H264_HIGH_444, null), null)), new C2565e(14, 48, 48, 22, 22, new c(68, new b(1, 174, null), null)), new C2565e(15, 52, 52, 24, 24, new c(42, new b(2, 102, null), null)), new C2565e(16, 64, 64, 14, 14, new c(56, new b(2, 140, null), null)), new C2565e(17, 72, 72, 16, 16, new c(36, new b(4, 92, null), null)), new C2565e(18, 80, 80, 18, 18, new c(48, new b(4, 114, null), null)), new C2565e(19, 88, 88, 20, 20, new c(56, new b(4, IjkMediaMeta.FF_PROFILE_H264_HIGH_444, null), null)), new C2565e(20, 96, 96, 22, 22, new c(68, new b(4, 174, null), null)), new C2565e(21, 104, 104, 24, 24, new c(56, new b(6, 136, null), null)), new C2565e(22, 120, 120, 18, 18, new c(68, new b(6, HideBottomViewOnScrollBehavior.EXIT_ANIMATION_DURATION, null), null)), new C2565e(23, 132, 132, 20, 20, new c(62, new b(8, Opcodes.IF_ICMPGT, null), null)), new C2565e(24, IjkMediaMeta.FF_PROFILE_H264_HIGH_444, IjkMediaMeta.FF_PROFILE_H264_HIGH_444, 22, 22, new c(62, new b(8, 156, null), new b(2, 155, null), null)), new C2565e(25, 8, 18, 6, 16, new c(7, new b(1, 5, null), null)), new C2565e(26, 8, 32, 6, 14, new c(11, new b(1, 10, null), null)), new C2565e(27, 12, 26, 10, 24, new c(14, new b(1, 16, null), null)), new C2565e(28, 12, 36, 10, 16, new c(18, new b(1, 22, null), null)), new C2565e(29, 16, 36, 14, 16, new c(24, new b(1, 32, null), null)), new C2565e(30, 16, 48, 14, 22, new c(28, new b(1, 49, null), null))};

    /* renamed from: b */
    public final int f6999b;

    /* renamed from: c */
    public final int f7000c;

    /* renamed from: d */
    public final int f7001d;

    /* renamed from: e */
    public final int f7002e;

    /* renamed from: f */
    public final int f7003f;

    /* renamed from: g */
    public final c f7004g;

    /* renamed from: h */
    public final int f7005h;

    /* renamed from: b.l.d.w.b.e$b */
    public static final class b {

        /* renamed from: a */
        public final int f7006a;

        /* renamed from: b */
        public final int f7007b;

        public b(int i2, int i3, a aVar) {
            this.f7006a = i2;
            this.f7007b = i3;
        }
    }

    public C2565e(int i2, int i3, int i4, int i5, int i6, c cVar) {
        this.f6999b = i2;
        this.f7000c = i3;
        this.f7001d = i4;
        this.f7002e = i5;
        this.f7003f = i6;
        this.f7004g = cVar;
        int i7 = cVar.f7008a;
        int i8 = 0;
        for (b bVar : cVar.f7009b) {
            i8 += (bVar.f7007b + i7) * bVar.f7006a;
        }
        this.f7005h = i8;
    }

    public String toString() {
        return String.valueOf(this.f6999b);
    }

    /* renamed from: b.l.d.w.b.e$c */
    public static final class c {

        /* renamed from: a */
        public final int f7008a;

        /* renamed from: b */
        public final b[] f7009b;

        public c(int i2, b bVar, a aVar) {
            this.f7008a = i2;
            this.f7009b = new b[]{bVar};
        }

        public c(int i2, b bVar, b bVar2, a aVar) {
            this.f7008a = i2;
            this.f7009b = new b[]{bVar, bVar2};
        }
    }
}
