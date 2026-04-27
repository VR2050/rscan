package B;

import androidx.fragment.app.Fragment;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public abstract class g extends RuntimeException {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final Fragment f73b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public g(Fragment fragment, String str) {
        super(str);
        j.f(fragment, "fragment");
        this.f73b = fragment;
    }

    public final Fragment a() {
        return this.f73b;
    }
}
