package im.uwrkaxlmjj.ui.hui.friendscircle_v1.utils;

import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentActivity;
import androidx.fragment.app.FragmentManager;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.listener.FragmentBackHandler;
import java.util.List;

/* JADX INFO: loaded from: classes5.dex */
public class BackHandlerHelper {
    public static boolean handleBackPress(FragmentManager fragmentManager) {
        List<Fragment> fragments = fragmentManager.getFragments();
        if (fragments == null) {
            return false;
        }
        for (int i = fragments.size() - 1; i >= 0; i--) {
            Fragment child = fragments.get(i);
            if (isFragmentBackHandled(child)) {
                return true;
            }
        }
        int i2 = fragmentManager.getBackStackEntryCount();
        if (i2 <= 0) {
            return false;
        }
        fragmentManager.popBackStack();
        return true;
    }

    public static boolean handleBackPress(Fragment fragment) {
        return handleBackPress(fragment.getChildFragmentManager());
    }

    public static boolean handleBackPress(FragmentActivity fragmentActivity) {
        return handleBackPress(fragmentActivity.getSupportFragmentManager());
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static boolean isFragmentBackHandled(Fragment fragment) {
        return fragment != 0 && fragment.isVisible() && fragment.getUserVisibleHint() && (fragment instanceof FragmentBackHandler) && ((FragmentBackHandler) fragment).onBackPressed();
    }
}
