package androidx.lifecycle;

import androidx.lifecycle.f;

/* JADX INFO: loaded from: classes.dex */
public final class DefaultLifecycleObserverAdapter implements i {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final InterfaceC0304b f5095a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final i f5096b;

    public /* synthetic */ class a {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        public static final /* synthetic */ int[] f5097a;

        static {
            int[] iArr = new int[f.a.values().length];
            try {
                iArr[f.a.ON_CREATE.ordinal()] = 1;
            } catch (NoSuchFieldError unused) {
            }
            try {
                iArr[f.a.ON_START.ordinal()] = 2;
            } catch (NoSuchFieldError unused2) {
            }
            try {
                iArr[f.a.ON_RESUME.ordinal()] = 3;
            } catch (NoSuchFieldError unused3) {
            }
            try {
                iArr[f.a.ON_PAUSE.ordinal()] = 4;
            } catch (NoSuchFieldError unused4) {
            }
            try {
                iArr[f.a.ON_STOP.ordinal()] = 5;
            } catch (NoSuchFieldError unused5) {
            }
            try {
                iArr[f.a.ON_DESTROY.ordinal()] = 6;
            } catch (NoSuchFieldError unused6) {
            }
            try {
                iArr[f.a.ON_ANY.ordinal()] = 7;
            } catch (NoSuchFieldError unused7) {
            }
            f5097a = iArr;
        }
    }

    public DefaultLifecycleObserverAdapter(InterfaceC0304b interfaceC0304b, i iVar) {
        t2.j.f(interfaceC0304b, "defaultLifecycleObserver");
        this.f5095a = interfaceC0304b;
        this.f5096b = iVar;
    }

    @Override // androidx.lifecycle.i
    public void d(k kVar, f.a aVar) {
        t2.j.f(kVar, "source");
        t2.j.f(aVar, "event");
        switch (a.f5097a[aVar.ordinal()]) {
            case 1:
                this.f5095a.c(kVar);
                break;
            case 2:
                this.f5095a.f(kVar);
                break;
            case 3:
                this.f5095a.a(kVar);
                break;
            case 4:
                this.f5095a.e(kVar);
                break;
            case 5:
                this.f5095a.g(kVar);
                break;
            case 6:
                this.f5095a.b(kVar);
                break;
            case 7:
                throw new IllegalArgumentException("ON_ANY must not been send by anybody");
        }
        i iVar = this.f5096b;
        if (iVar != null) {
            iVar.d(kVar, aVar);
        }
    }
}
