package h2;

import java.io.Serializable;
import java.util.concurrent.atomic.AtomicReferenceFieldUpdater;
import kotlin.Lazy;
import kotlin.jvm.internal.DefaultConstructorMarker;
import s2.InterfaceC0688a;

/* JADX INFO: loaded from: classes.dex */
final class l implements Lazy, Serializable {

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    public static final a f9278e = new a(null);

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private static final AtomicReferenceFieldUpdater f9279f = AtomicReferenceFieldUpdater.newUpdater(l.class, Object.class, "c");

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private volatile InterfaceC0688a f9280b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private volatile Object f9281c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final Object f9282d;

    public static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private a() {
        }
    }

    public l(InterfaceC0688a interfaceC0688a) {
        t2.j.f(interfaceC0688a, "initializer");
        this.f9280b = interfaceC0688a;
        o oVar = o.f9286a;
        this.f9281c = oVar;
        this.f9282d = oVar;
    }

    public boolean a() {
        return this.f9281c != o.f9286a;
    }

    @Override // kotlin.Lazy
    public Object getValue() {
        Object obj = this.f9281c;
        o oVar = o.f9286a;
        if (obj != oVar) {
            return obj;
        }
        InterfaceC0688a interfaceC0688a = this.f9280b;
        if (interfaceC0688a != null) {
            Object objA = interfaceC0688a.a();
            if (androidx.concurrent.futures.b.a(f9279f, this, oVar, objA)) {
                this.f9280b = null;
                return objA;
            }
        }
        return this.f9281c;
    }

    public String toString() {
        return a() ? String.valueOf(getValue()) : "Lazy value not initialized yet.";
    }
}
