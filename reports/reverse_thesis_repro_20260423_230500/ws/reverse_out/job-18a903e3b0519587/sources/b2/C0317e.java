package b2;

import com.facebook.soloader.E;

/* JADX INFO: renamed from: b2.e, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public class C0317e implements InterfaceC0320h {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final InterfaceC0320h[] f5406a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private int f5407b = 0;

    public C0317e(InterfaceC0320h... interfaceC0320hArr) {
        this.f5406a = interfaceC0320hArr;
    }

    @Override // b2.InterfaceC0320h
    public boolean a(UnsatisfiedLinkError unsatisfiedLinkError, E[] eArr) {
        int i3;
        InterfaceC0320h[] interfaceC0320hArr;
        do {
            i3 = this.f5407b;
            interfaceC0320hArr = this.f5406a;
            if (i3 >= interfaceC0320hArr.length) {
                return false;
            }
            this.f5407b = i3 + 1;
        } while (!interfaceC0320hArr[i3].a(unsatisfiedLinkError, eArr));
        return true;
    }
}
