package h2;

import java.io.Serializable;
import kotlin.Lazy;
import kotlin.jvm.internal.DefaultConstructorMarker;
import s2.InterfaceC0688a;

/* JADX INFO: loaded from: classes.dex */
final class m implements Lazy, Serializable {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private InterfaceC0688a f9283b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private volatile Object f9284c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final Object f9285d;

    public m(InterfaceC0688a interfaceC0688a, Object obj) {
        t2.j.f(interfaceC0688a, "initializer");
        this.f9283b = interfaceC0688a;
        this.f9284c = o.f9286a;
        this.f9285d = obj == null ? this : obj;
    }

    public boolean a() {
        return this.f9284c != o.f9286a;
    }

    @Override // kotlin.Lazy
    public Object getValue() {
        Object objA;
        Object obj = this.f9284c;
        o oVar = o.f9286a;
        if (obj != oVar) {
            return obj;
        }
        synchronized (this.f9285d) {
            objA = this.f9284c;
            if (objA == oVar) {
                InterfaceC0688a interfaceC0688a = this.f9283b;
                t2.j.c(interfaceC0688a);
                objA = interfaceC0688a.a();
                this.f9284c = objA;
                this.f9283b = null;
            }
        }
        return objA;
    }

    public String toString() {
        return a() ? String.valueOf(getValue()) : "Lazy value not initialized yet.";
    }

    public /* synthetic */ m(InterfaceC0688a interfaceC0688a, Object obj, int i3, DefaultConstructorMarker defaultConstructorMarker) {
        this(interfaceC0688a, (i3 & 2) != 0 ? null : obj);
    }
}
