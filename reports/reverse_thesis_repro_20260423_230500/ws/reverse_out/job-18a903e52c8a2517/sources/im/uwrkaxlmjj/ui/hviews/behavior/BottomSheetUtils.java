package im.uwrkaxlmjj.ui.hviews.behavior;

import android.view.View;
import android.view.ViewGroup;
import androidx.coordinatorlayout.widget.CoordinatorLayout;
import androidx.viewpager.widget.ViewPager;

/* JADX INFO: loaded from: classes5.dex */
public final class BottomSheetUtils {
    public static void setupViewPager(ViewPager viewPager) {
        View bottomSheetParent = findBottomSheetParent(viewPager);
        if (bottomSheetParent != null) {
            viewPager.addOnPageChangeListener(new BottomSheetViewPagerListener(viewPager, bottomSheetParent));
        }
    }

    private static class BottomSheetViewPagerListener extends ViewPager.SimpleOnPageChangeListener {
        private final ViewPagerBottomSheetBehavior<View> behavior;
        private final ViewPager viewPager;

        private BottomSheetViewPagerListener(ViewPager viewPager, View bottomSheetParent) {
            this.viewPager = viewPager;
            this.behavior = ViewPagerBottomSheetBehavior.from(bottomSheetParent);
        }

        @Override // androidx.viewpager.widget.ViewPager.SimpleOnPageChangeListener, androidx.viewpager.widget.ViewPager.OnPageChangeListener
        public void onPageSelected(int position) {
            ViewPager viewPager = this.viewPager;
            final ViewPagerBottomSheetBehavior<View> viewPagerBottomSheetBehavior = this.behavior;
            viewPagerBottomSheetBehavior.getClass();
            viewPager.post(new Runnable() { // from class: im.uwrkaxlmjj.ui.hviews.behavior.-$$Lambda$gRqPZFu5NjIPYiAX7dSUVOQSSIw
                @Override // java.lang.Runnable
                public final void run() {
                    viewPagerBottomSheetBehavior.invalidateScrollingChild();
                }
            });
        }
    }

    private static View findBottomSheetParent(View view) {
        View current = view;
        while (true) {
            View view2 = null;
            if (current == null) {
                return null;
            }
            ViewGroup.LayoutParams params = current.getLayoutParams();
            if ((params instanceof CoordinatorLayout.LayoutParams) && (((CoordinatorLayout.LayoutParams) params).getBehavior() instanceof ViewPagerBottomSheetBehavior)) {
                return current;
            }
            Object parent = current.getParent();
            if (parent != null && (parent instanceof View)) {
                view2 = (View) parent;
            }
            current = view2;
        }
    }
}
