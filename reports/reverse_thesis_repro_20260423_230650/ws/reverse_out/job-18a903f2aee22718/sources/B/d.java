package B;

import android.view.ViewGroup;
import androidx.fragment.app.Fragment;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public final class d extends g {

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final ViewGroup f72c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(Fragment fragment, ViewGroup viewGroup) {
        super(fragment, "Attempting to use <fragment> tag to add fragment " + fragment + " to container " + viewGroup);
        j.f(fragment, "fragment");
        this.f72c = viewGroup;
    }
}
