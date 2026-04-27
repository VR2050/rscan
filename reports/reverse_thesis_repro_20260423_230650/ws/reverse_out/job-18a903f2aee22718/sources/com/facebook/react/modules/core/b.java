package com.facebook.react.modules.core;

import android.view.Choreographer;
import com.facebook.react.bridge.UiThreadUtil;
import h2.r;
import java.util.ArrayDeque;
import kotlin.enums.EnumEntries;
import kotlin.jvm.internal.DefaultConstructorMarker;
import m2.AbstractC0628a;
import p1.InterfaceC0648b;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public final class b {

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    public static final C0110b f7042f = new C0110b(null);

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private static b f7043g;

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private InterfaceC0648b.a f7044a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final ArrayDeque[] f7045b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private int f7046c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private boolean f7047d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final Choreographer.FrameCallback f7048e;

    /* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
    /* JADX WARN: Unknown enum class pattern. Please report as an issue! */
    public static final class a {

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        public static final a f7049c = new a("PERF_MARKERS", 0, 0);

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        public static final a f7050d = new a("DISPATCH_UI", 1, 1);

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        public static final a f7051e = new a("NATIVE_ANIMATED_MODULE", 2, 2);

        /* JADX INFO: renamed from: f, reason: collision with root package name */
        public static final a f7052f = new a("TIMERS_EVENTS", 3, 3);

        /* JADX INFO: renamed from: g, reason: collision with root package name */
        public static final a f7053g = new a("IDLE_EVENT", 4, 4);

        /* JADX INFO: renamed from: h, reason: collision with root package name */
        private static final /* synthetic */ a[] f7054h;

        /* JADX INFO: renamed from: i, reason: collision with root package name */
        private static final /* synthetic */ EnumEntries f7055i;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private final int f7056b;

        static {
            a[] aVarArrA = a();
            f7054h = aVarArrA;
            f7055i = AbstractC0628a.a(aVarArrA);
        }

        private a(String str, int i3, int i4) {
            this.f7056b = i4;
        }

        private static final /* synthetic */ a[] a() {
            return new a[]{f7049c, f7050d, f7051e, f7052f, f7053g};
        }

        public static EnumEntries b() {
            return f7055i;
        }

        public static a valueOf(String str) {
            return (a) Enum.valueOf(a.class, str);
        }

        public static a[] values() {
            return (a[]) f7054h.clone();
        }

        public final int c() {
            return this.f7056b;
        }
    }

    /* JADX INFO: renamed from: com.facebook.react.modules.core.b$b, reason: collision with other inner class name */
    public static final class C0110b {
        public /* synthetic */ C0110b(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public final b a() {
            b bVar = b.f7043g;
            if (bVar != null) {
                return bVar;
            }
            throw new IllegalStateException("ReactChoreographer needs to be initialized.");
        }

        public final void b(InterfaceC0648b interfaceC0648b) {
            j.f(interfaceC0648b, "choreographerProvider");
            if (b.f7043g == null) {
                b.f7043g = new b(interfaceC0648b, null);
            }
        }

        private C0110b() {
        }
    }

    public /* synthetic */ b(InterfaceC0648b interfaceC0648b, DefaultConstructorMarker defaultConstructorMarker) {
        this(interfaceC0648b);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final void d(b bVar, InterfaceC0648b interfaceC0648b) {
        bVar.f7044a = interfaceC0648b.a();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final void g(b bVar, long j3) {
        synchronized (bVar.f7045b) {
            try {
                bVar.f7047d = false;
                int length = bVar.f7045b.length;
                for (int i3 = 0; i3 < length; i3++) {
                    ArrayDeque arrayDeque = bVar.f7045b[i3];
                    int size = arrayDeque.size();
                    for (int i4 = 0; i4 < size; i4++) {
                        Choreographer.FrameCallback frameCallback = (Choreographer.FrameCallback) arrayDeque.pollFirst();
                        if (frameCallback != null) {
                            frameCallback.doFrame(j3);
                            bVar.f7046c--;
                        } else {
                            Y.a.m("ReactNative", "Tried to execute non-existent frame callback");
                        }
                    }
                }
                bVar.j();
                r rVar = r.f9288a;
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public static final b h() {
        return f7042f.a();
    }

    public static final void i(InterfaceC0648b interfaceC0648b) {
        f7042f.b(interfaceC0648b);
    }

    private final void j() {
        Z0.a.a(this.f7046c >= 0);
        if (this.f7046c == 0 && this.f7047d) {
            InterfaceC0648b.a aVar = this.f7044a;
            if (aVar != null) {
                aVar.b(this.f7048e);
            }
            this.f7047d = false;
        }
    }

    private final void l() {
        if (this.f7047d) {
            return;
        }
        InterfaceC0648b.a aVar = this.f7044a;
        if (aVar == null) {
            UiThreadUtil.runOnUiThread(new Runnable() { // from class: A1.j
                @Override // java.lang.Runnable
                public final void run() {
                    com.facebook.react.modules.core.b.m(this.f51b);
                }
            });
        } else {
            aVar.a(this.f7048e);
            this.f7047d = true;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final void m(b bVar) {
        synchronized (bVar.f7045b) {
            bVar.l();
            r rVar = r.f9288a;
        }
    }

    public final void k(a aVar, Choreographer.FrameCallback frameCallback) {
        j.f(aVar, "type");
        j.f(frameCallback, "callback");
        synchronized (this.f7045b) {
            this.f7045b[aVar.c()].addLast(frameCallback);
            boolean z3 = true;
            int i3 = this.f7046c + 1;
            this.f7046c = i3;
            if (i3 <= 0) {
                z3 = false;
            }
            Z0.a.a(z3);
            l();
            r rVar = r.f9288a;
        }
    }

    public final void n(a aVar, Choreographer.FrameCallback frameCallback) {
        j.f(aVar, "type");
        synchronized (this.f7045b) {
            try {
                if (this.f7045b[aVar.c()].removeFirstOccurrence(frameCallback)) {
                    this.f7046c--;
                    j();
                } else {
                    Y.a.m("ReactNative", "Tried to remove non-existent frame callback");
                }
                r rVar = r.f9288a;
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    private b(final InterfaceC0648b interfaceC0648b) {
        int size = a.b().size();
        ArrayDeque[] arrayDequeArr = new ArrayDeque[size];
        for (int i3 = 0; i3 < size; i3++) {
            arrayDequeArr[i3] = new ArrayDeque();
        }
        this.f7045b = arrayDequeArr;
        this.f7048e = new Choreographer.FrameCallback() { // from class: A1.h
            @Override // android.view.Choreographer.FrameCallback
            public final void doFrame(long j3) {
                com.facebook.react.modules.core.b.g(this.f48a, j3);
            }
        };
        UiThreadUtil.runOnUiThread(new Runnable() { // from class: A1.i
            @Override // java.lang.Runnable
            public final void run() {
                com.facebook.react.modules.core.b.d(this.f49b, interfaceC0648b);
            }
        });
    }
}
