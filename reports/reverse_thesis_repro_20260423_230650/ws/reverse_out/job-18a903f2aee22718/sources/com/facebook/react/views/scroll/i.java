package com.facebook.react.views.scroll;

import com.facebook.react.bridge.ReadableArray;
import com.facebook.react.uimanager.C0444f0;
import h2.n;
import i2.D;
import java.util.Map;
import kotlin.jvm.internal.DefaultConstructorMarker;

/* JADX INFO: loaded from: classes.dex */
public abstract class i {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    public static final a f7980a = new a(null);

    public static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private final void d(b bVar, Object obj, ReadableArray readableArray) {
            bVar.scrollTo(obj, new c(Math.round(C0444f0.g(readableArray.getDouble(0))), Math.round(C0444f0.g(readableArray.getDouble(1))), readableArray.getBoolean(2)));
        }

        private final void e(b bVar, Object obj, ReadableArray readableArray) {
            bVar.scrollToEnd(obj, new d(readableArray.getBoolean(0)));
        }

        public final Map a() {
            return D.g(n.a("scrollTo", 1), n.a("scrollToEnd", 2), n.a("flashScrollIndicators", 3));
        }

        public final void b(b bVar, Object obj, int i3, ReadableArray readableArray) {
            t2.j.f(bVar, "viewManager");
            if (obj == null) {
                throw new IllegalStateException("Required value was null.");
            }
            if (i3 == 1) {
                if (readableArray == null) {
                    throw new IllegalStateException("Required value was null.");
                }
                d(bVar, obj, readableArray);
                return;
            }
            if (i3 == 2) {
                if (readableArray == null) {
                    throw new IllegalStateException("Required value was null.");
                }
                e(bVar, obj, readableArray);
            } else {
                if (i3 == 3) {
                    bVar.flashScrollIndicators(obj);
                    return;
                }
                throw new IllegalArgumentException("Unsupported command " + i3 + " received by " + bVar.getClass().getSimpleName() + ".");
            }
        }

        public final void c(b bVar, Object obj, String str, ReadableArray readableArray) {
            t2.j.f(bVar, "viewManager");
            t2.j.f(str, "commandType");
            if (obj == null) {
                throw new IllegalStateException("Required value was null.");
            }
            int iHashCode = str.hashCode();
            if (iHashCode != -402165208) {
                if (iHashCode != 28425985) {
                    if (iHashCode == 2055114131 && str.equals("scrollToEnd")) {
                        if (readableArray == null) {
                            throw new IllegalStateException("Required value was null.");
                        }
                        e(bVar, obj, readableArray);
                        return;
                    }
                } else if (str.equals("flashScrollIndicators")) {
                    bVar.flashScrollIndicators(obj);
                    return;
                }
            } else if (str.equals("scrollTo")) {
                if (readableArray == null) {
                    throw new IllegalStateException("Required value was null.");
                }
                d(bVar, obj, readableArray);
                return;
            }
            throw new IllegalArgumentException("Unsupported command " + str + " received by " + bVar.getClass().getSimpleName() + ".");
        }

        private a() {
        }
    }

    public interface b {
        void flashScrollIndicators(Object obj);

        void scrollTo(Object obj, c cVar);

        void scrollToEnd(Object obj, d dVar);
    }

    public static final class c {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        public final int f7981a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        public final int f7982b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        public final boolean f7983c;

        public c(int i3, int i4, boolean z3) {
            this.f7981a = i3;
            this.f7982b = i4;
            this.f7983c = z3;
        }
    }

    public static final class d {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        public final boolean f7984a;

        public d(boolean z3) {
            this.f7984a = z3;
        }
    }

    public static final Map a() {
        return f7980a.a();
    }

    public static final void b(b bVar, Object obj, int i3, ReadableArray readableArray) {
        f7980a.b(bVar, obj, i3, readableArray);
    }

    public static final void c(b bVar, Object obj, String str, ReadableArray readableArray) {
        f7980a.c(bVar, obj, str, readableArray);
    }
}
