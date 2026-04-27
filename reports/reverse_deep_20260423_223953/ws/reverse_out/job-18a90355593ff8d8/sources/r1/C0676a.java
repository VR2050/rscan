package r1;

import O1.d;
import com.facebook.react.bridge.WritableMap;
import t2.j;

/* JADX INFO: renamed from: r1.a, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public final class C0676a extends d {

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private final String f9985h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private final WritableMap f9986i;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0676a(String str, WritableMap writableMap, int i3, int i4) {
        super(i3, i4);
        j.f(str, "eventName");
        this.f9985h = str;
        this.f9986i = writableMap;
    }

    @Override // O1.d
    protected WritableMap j() {
        return this.f9986i;
    }

    @Override // O1.d
    public String k() {
        return this.f9985h;
    }
}
