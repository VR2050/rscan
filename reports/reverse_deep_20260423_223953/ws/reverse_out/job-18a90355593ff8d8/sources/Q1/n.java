package Q1;

import kotlin.enums.EnumEntries;
import kotlin.jvm.internal.DefaultConstructorMarker;
import m2.AbstractC0628a;
import org.chromium.support_lib_boundary.WebSettingsBoundaryInterface;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* JADX INFO: loaded from: classes.dex */
public abstract class n {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    public static final f f2477b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    public static final n f2478c = new n("ALL", 0) { // from class: Q1.n.a
        {
            DefaultConstructorMarker defaultConstructorMarker = null;
        }

        @Override // Q1.n
        public int b() {
            return 8;
        }
    };

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    public static final n f2479d = new n("LEFT", 1) { // from class: Q1.n.i
        {
            DefaultConstructorMarker defaultConstructorMarker = null;
        }

        @Override // Q1.n
        public int b() {
            return 0;
        }
    };

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    public static final n f2480e = new n("RIGHT", 2) { // from class: Q1.n.j
        {
            DefaultConstructorMarker defaultConstructorMarker = null;
        }

        @Override // Q1.n
        public int b() {
            return 2;
        }
    };

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    public static final n f2481f = new n("TOP", 3) { // from class: Q1.n.l
        {
            DefaultConstructorMarker defaultConstructorMarker = null;
        }

        @Override // Q1.n
        public int b() {
            return 1;
        }
    };

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    public static final n f2482g = new n("BOTTOM", 4) { // from class: Q1.n.e
        {
            DefaultConstructorMarker defaultConstructorMarker = null;
        }

        @Override // Q1.n
        public int b() {
            return 3;
        }
    };

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    public static final n f2483h = new n("START", 5) { // from class: Q1.n.k
        {
            DefaultConstructorMarker defaultConstructorMarker = null;
        }

        @Override // Q1.n
        public int b() {
            return 4;
        }
    };

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    public static final n f2484i = new n("END", 6) { // from class: Q1.n.g
        {
            DefaultConstructorMarker defaultConstructorMarker = null;
        }

        @Override // Q1.n
        public int b() {
            return 5;
        }
    };

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    public static final n f2485j = new n("HORIZONTAL", 7) { // from class: Q1.n.h
        {
            DefaultConstructorMarker defaultConstructorMarker = null;
        }

        @Override // Q1.n
        public int b() {
            return 6;
        }
    };

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    public static final n f2486k = new n("VERTICAL", 8) { // from class: Q1.n.m
        {
            DefaultConstructorMarker defaultConstructorMarker = null;
        }

        @Override // Q1.n
        public int b() {
            return 7;
        }
    };

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    public static final n f2487l = new n("BLOCK_START", 9) { // from class: Q1.n.d
        {
            DefaultConstructorMarker defaultConstructorMarker = null;
        }

        @Override // Q1.n
        public int b() {
            return 11;
        }
    };

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    public static final n f2488m = new n("BLOCK_END", 10) { // from class: Q1.n.c
        {
            DefaultConstructorMarker defaultConstructorMarker = null;
        }

        @Override // Q1.n
        public int b() {
            return 10;
        }
    };

    /* JADX INFO: renamed from: n, reason: collision with root package name */
    public static final n f2489n = new n("BLOCK", 11) { // from class: Q1.n.b
        {
            DefaultConstructorMarker defaultConstructorMarker = null;
        }

        @Override // Q1.n
        public int b() {
            return 9;
        }
    };

    /* JADX INFO: renamed from: o, reason: collision with root package name */
    private static final /* synthetic */ n[] f2490o;

    /* JADX INFO: renamed from: p, reason: collision with root package name */
    private static final /* synthetic */ EnumEntries f2491p;

    public static final class f {
        public /* synthetic */ f(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public final n a(int i3) {
            switch (i3) {
                case WebSettingsBoundaryInterface.ForceDarkBehavior.FORCE_DARK_ONLY /* 0 */:
                    return n.f2479d;
                case 1:
                    return n.f2481f;
                case 2:
                    return n.f2480e;
                case 3:
                    return n.f2482g;
                case 4:
                    return n.f2483h;
                case 5:
                    return n.f2484i;
                case 6:
                    return n.f2485j;
                case 7:
                    return n.f2486k;
                case 8:
                    return n.f2478c;
                case 9:
                    return n.f2489n;
                case 10:
                    return n.f2488m;
                case 11:
                    return n.f2487l;
                default:
                    throw new IllegalArgumentException("Unknown spacing type: " + i3);
            }
        }

        private f() {
        }
    }

    static {
        n[] nVarArrA = a();
        f2490o = nVarArrA;
        f2491p = AbstractC0628a.a(nVarArrA);
        f2477b = new f(null);
    }

    public /* synthetic */ n(String str, int i3, DefaultConstructorMarker defaultConstructorMarker) {
        this(str, i3);
    }

    private static final /* synthetic */ n[] a() {
        return new n[]{f2478c, f2479d, f2480e, f2481f, f2482g, f2483h, f2484i, f2485j, f2486k, f2487l, f2488m, f2489n};
    }

    public static n valueOf(String str) {
        return (n) Enum.valueOf(n.class, str);
    }

    public static n[] values() {
        return (n[]) f2490o.clone();
    }

    public abstract int b();

    private n(String str, int i3) {
    }
}
