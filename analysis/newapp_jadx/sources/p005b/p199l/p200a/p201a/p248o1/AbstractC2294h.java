package p005b.p199l.p200a.p201a.p248o1;

import androidx.annotation.Nullable;
import java.util.ArrayList;
import java.util.Map;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;

/* renamed from: b.l.a.a.o1.h */
/* loaded from: classes.dex */
public abstract class AbstractC2294h implements InterfaceC2321m {

    @Nullable
    private C2324p dataSpec;
    private final boolean isNetwork;
    private int listenerCount;
    private final ArrayList<InterfaceC2291f0> listeners = new ArrayList<>(1);

    public AbstractC2294h(boolean z) {
        this.isNetwork = z;
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m
    public final void addTransferListener(InterfaceC2291f0 interfaceC2291f0) {
        if (this.listeners.contains(interfaceC2291f0)) {
            return;
        }
        this.listeners.add(interfaceC2291f0);
        this.listenerCount++;
    }

    public final void bytesTransferred(int i2) {
        C2324p c2324p = this.dataSpec;
        int i3 = C2344d0.f6035a;
        for (int i4 = 0; i4 < this.listenerCount; i4++) {
            this.listeners.get(i4).mo2194f(this, c2324p, this.isNetwork, i2);
        }
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m
    public /* synthetic */ Map getResponseHeaders() {
        return C2320l.m2265a(this);
    }

    public final void transferEnded() {
        C2324p c2324p = this.dataSpec;
        int i2 = C2344d0.f6035a;
        for (int i3 = 0; i3 < this.listenerCount; i3++) {
            this.listeners.get(i3).mo2192a(this, c2324p, this.isNetwork);
        }
        this.dataSpec = null;
    }

    public final void transferInitializing(C2324p c2324p) {
        for (int i2 = 0; i2 < this.listenerCount; i2++) {
            this.listeners.get(i2).mo2195h(this, c2324p, this.isNetwork);
        }
    }

    public final void transferStarted(C2324p c2324p) {
        this.dataSpec = c2324p;
        for (int i2 = 0; i2 < this.listenerCount; i2++) {
            this.listeners.get(i2).mo2193b(this, c2324p, this.isNetwork);
        }
    }
}
