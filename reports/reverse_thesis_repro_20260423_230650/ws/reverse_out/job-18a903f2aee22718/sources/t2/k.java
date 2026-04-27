package t2;

import java.io.Serializable;

/* JADX INFO: loaded from: classes.dex */
public abstract class k implements g, Serializable {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final int f10209b;

    public k(int i3) {
        this.f10209b = i3;
    }

    public String toString() {
        String strE = u.e(this);
        j.e(strE, "renderLambdaToString(...)");
        return strE;
    }
}
