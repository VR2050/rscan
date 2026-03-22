package p005b.p143g.p144a.p147m.p156v.p158d;

import androidx.annotation.NonNull;
import java.util.Objects;
import p005b.p143g.p144a.p147m.p150t.InterfaceC1655w;

/* renamed from: b.g.a.m.v.d.b */
/* loaded from: classes.dex */
public class C1723b implements InterfaceC1655w<byte[]> {

    /* renamed from: c */
    public final byte[] f2551c;

    public C1723b(byte[] bArr) {
        Objects.requireNonNull(bArr, "Argument must not be null");
        this.f2551c = bArr;
    }

    @Override // p005b.p143g.p144a.p147m.p150t.InterfaceC1655w
    @NonNull
    /* renamed from: a */
    public Class<byte[]> mo947a() {
        return byte[].class;
    }

    @Override // p005b.p143g.p144a.p147m.p150t.InterfaceC1655w
    @NonNull
    public byte[] get() {
        return this.f2551c;
    }

    @Override // p005b.p143g.p144a.p147m.p150t.InterfaceC1655w
    public int getSize() {
        return this.f2551c.length;
    }

    @Override // p005b.p143g.p144a.p147m.p150t.InterfaceC1655w
    public void recycle() {
    }
}
