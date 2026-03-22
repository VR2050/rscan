package p005b.p362y.p363a.p368h;

import p005b.p362y.p363a.p367g.C2932a;

/* renamed from: b.y.a.h.a */
/* loaded from: classes2.dex */
public abstract class AbstractC2935a implements InterfaceC2937c {
    public InterfaceC2936b mPlayerInitSuccessListener;

    public InterfaceC2936b getPlayerPreparedSuccessListener() {
        return this.mPlayerInitSuccessListener;
    }

    public void initSuccess(C2932a c2932a) {
        InterfaceC2936b interfaceC2936b = this.mPlayerInitSuccessListener;
        if (interfaceC2936b != null) {
            interfaceC2936b.m3403a(getMediaPlayer(), c2932a);
        }
    }

    public void setPlayerInitSuccessListener(InterfaceC2936b interfaceC2936b) {
        this.mPlayerInitSuccessListener = interfaceC2936b;
    }
}
