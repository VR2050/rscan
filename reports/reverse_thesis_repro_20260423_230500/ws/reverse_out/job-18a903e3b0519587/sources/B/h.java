package B;

import android.view.ViewGroup;
import androidx.fragment.app.Fragment;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public final class h extends g {

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final ViewGroup f74c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public h(Fragment fragment, ViewGroup viewGroup) {
        super(fragment, "Attempting to add fragment " + fragment + " to container " + viewGroup + " which is not a FragmentContainerView");
        j.f(fragment, "fragment");
        j.f(viewGroup, "container");
        this.f74c = viewGroup;
    }
}
