package O1;

import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.WritableMap;
import com.facebook.react.uimanager.C0444f0;

/* JADX INFO: loaded from: classes.dex */
public final class c extends d {

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private final int f2037h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private final int f2038i;

    public c(int i3, int i4, int i5, int i6) {
        super(i3, i4);
        this.f2037h = i5;
        this.f2038i = i6;
    }

    @Override // O1.d
    protected WritableMap j() {
        WritableMap writableMapCreateMap = Arguments.createMap();
        writableMapCreateMap.putDouble("width", C0444f0.f(this.f2037h));
        writableMapCreateMap.putDouble("height", C0444f0.f(this.f2038i));
        t2.j.c(writableMapCreateMap);
        return writableMapCreateMap;
    }

    @Override // O1.d
    public String k() {
        return "topContentSizeChange";
    }

    public c(int i3, int i4, int i5) {
        this(-1, i3, i4, i5);
    }
}
