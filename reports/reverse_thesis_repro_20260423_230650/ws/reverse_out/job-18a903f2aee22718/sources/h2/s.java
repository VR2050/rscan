package h2;

import java.io.Serializable;
import kotlin.Lazy;
import s2.InterfaceC0688a;

/* JADX INFO: loaded from: classes.dex */
public final class s implements Lazy, Serializable {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private InterfaceC0688a f9289b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private Object f9290c;

    public s(InterfaceC0688a interfaceC0688a) {
        t2.j.f(interfaceC0688a, "initializer");
        this.f9289b = interfaceC0688a;
        this.f9290c = o.f9286a;
    }

    public boolean a() {
        return this.f9290c != o.f9286a;
    }

    @Override // kotlin.Lazy
    public Object getValue() {
        if (this.f9290c == o.f9286a) {
            InterfaceC0688a interfaceC0688a = this.f9289b;
            t2.j.c(interfaceC0688a);
            this.f9290c = interfaceC0688a.a();
            this.f9289b = null;
        }
        return this.f9290c;
    }

    public String toString() {
        return a() ? String.valueOf(getValue()) : "Lazy value not initialized yet.";
    }
}
