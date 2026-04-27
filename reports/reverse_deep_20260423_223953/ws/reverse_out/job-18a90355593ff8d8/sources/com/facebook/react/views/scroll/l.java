package com.facebook.react.views.scroll;

import h2.C0562h;
import kotlin.enums.EnumEntries;
import kotlin.jvm.internal.DefaultConstructorMarker;
import m2.AbstractC0628a;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* JADX INFO: loaded from: classes.dex */
public final class l {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    public static final a f8014b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    public static final l f8015c = new l("BEGIN_DRAG", 0);

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    public static final l f8016d = new l("END_DRAG", 1);

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    public static final l f8017e = new l("SCROLL", 2);

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    public static final l f8018f = new l("MOMENTUM_BEGIN", 3);

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    public static final l f8019g = new l("MOMENTUM_END", 4);

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private static final /* synthetic */ l[] f8020h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private static final /* synthetic */ EnumEntries f8021i;

    public static final class a {

        /* JADX INFO: renamed from: com.facebook.react.views.scroll.l$a$a, reason: collision with other inner class name */
        public /* synthetic */ class C0119a {

            /* JADX INFO: renamed from: a, reason: collision with root package name */
            public static final /* synthetic */ int[] f8022a;

            static {
                int[] iArr = new int[l.values().length];
                try {
                    iArr[l.f8015c.ordinal()] = 1;
                } catch (NoSuchFieldError unused) {
                }
                try {
                    iArr[l.f8016d.ordinal()] = 2;
                } catch (NoSuchFieldError unused2) {
                }
                try {
                    iArr[l.f8017e.ordinal()] = 3;
                } catch (NoSuchFieldError unused3) {
                }
                try {
                    iArr[l.f8018f.ordinal()] = 4;
                } catch (NoSuchFieldError unused4) {
                }
                try {
                    iArr[l.f8019g.ordinal()] = 5;
                } catch (NoSuchFieldError unused5) {
                }
                f8022a = iArr;
            }
        }

        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public final String a(l lVar) {
            t2.j.f(lVar, "type");
            int i3 = C0119a.f8022a[lVar.ordinal()];
            if (i3 == 1) {
                return "topScrollBeginDrag";
            }
            if (i3 == 2) {
                return "topScrollEndDrag";
            }
            if (i3 == 3) {
                return "topScroll";
            }
            if (i3 == 4) {
                return "topMomentumScrollBegin";
            }
            if (i3 == 5) {
                return "topMomentumScrollEnd";
            }
            throw new C0562h();
        }

        private a() {
        }
    }

    static {
        l[] lVarArrA = a();
        f8020h = lVarArrA;
        f8021i = AbstractC0628a.a(lVarArrA);
        f8014b = new a(null);
    }

    private l(String str, int i3) {
    }

    private static final /* synthetic */ l[] a() {
        return new l[]{f8015c, f8016d, f8017e, f8018f, f8019g};
    }

    public static final String b(l lVar) {
        return f8014b.a(lVar);
    }

    public static l valueOf(String str) {
        return (l) Enum.valueOf(l.class, str);
    }

    public static l[] values() {
        return (l[]) f8020h.clone();
    }
}
