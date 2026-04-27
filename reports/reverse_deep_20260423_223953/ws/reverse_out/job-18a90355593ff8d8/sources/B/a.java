package B;

import androidx.fragment.app.Fragment;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public final class a extends g {

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final String f54c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(Fragment fragment, String str) {
        super(fragment, "Attempting to reuse fragment " + fragment + " with previous ID " + str);
        j.f(fragment, "fragment");
        j.f(str, "previousFragmentId");
        this.f54c = str;
    }
}
