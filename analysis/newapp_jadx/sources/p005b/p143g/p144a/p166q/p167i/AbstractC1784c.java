package p005b.p143g.p144a.p166q.p167i;

import android.graphics.drawable.Drawable;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p143g.p144a.p166q.InterfaceC1775b;
import p005b.p143g.p144a.p170s.C1807i;

/* renamed from: b.g.a.q.i.c */
/* loaded from: classes.dex */
public abstract class AbstractC1784c<T> implements InterfaceC1790i<T> {
    private final int height;

    @Nullable
    private InterfaceC1775b request;
    private final int width;

    public AbstractC1784c() {
        this(Integer.MIN_VALUE, Integer.MIN_VALUE);
    }

    @Override // p005b.p143g.p144a.p166q.p167i.InterfaceC1790i
    @Nullable
    public final InterfaceC1775b getRequest() {
        return this.request;
    }

    @Override // p005b.p143g.p144a.p166q.p167i.InterfaceC1790i
    public final void getSize(@NonNull InterfaceC1789h interfaceC1789h) {
        interfaceC1789h.mo1111a(this.width, this.height);
    }

    @Override // p005b.p143g.p144a.p163n.InterfaceC1755i
    public void onDestroy() {
    }

    @Override // p005b.p143g.p144a.p166q.p167i.InterfaceC1790i
    public void onLoadFailed(@Nullable Drawable drawable) {
    }

    @Override // p005b.p143g.p144a.p166q.p167i.InterfaceC1790i
    public void onLoadStarted(@Nullable Drawable drawable) {
    }

    @Override // p005b.p143g.p144a.p163n.InterfaceC1755i
    public void onStart() {
    }

    @Override // p005b.p143g.p144a.p163n.InterfaceC1755i
    public void onStop() {
    }

    @Override // p005b.p143g.p144a.p166q.p167i.InterfaceC1790i
    public final void removeCallback(@NonNull InterfaceC1789h interfaceC1789h) {
    }

    @Override // p005b.p143g.p144a.p166q.p167i.InterfaceC1790i
    public final void setRequest(@Nullable InterfaceC1775b interfaceC1775b) {
        this.request = interfaceC1775b;
    }

    public AbstractC1784c(int i2, int i3) {
        if (!C1807i.m1152i(i2, i3)) {
            throw new IllegalArgumentException(C1499a.m629o("Width and height must both be > 0 or Target#SIZE_ORIGINAL, but given width: ", i2, " and height: ", i3));
        }
        this.width = i2;
        this.height = i3;
    }
}
