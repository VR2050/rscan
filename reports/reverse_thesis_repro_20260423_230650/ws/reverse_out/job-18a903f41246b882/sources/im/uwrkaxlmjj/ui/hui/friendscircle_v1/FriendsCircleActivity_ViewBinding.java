package im.uwrkaxlmjj.ui.hui.friendscircle_v1;

import android.view.View;
import butterknife.Unbinder;
import butterknife.internal.Utils;
import com.tablayout.SlidingTabLayout;
import im.uwrkaxlmjj.ui.hviews.NoScrollViewPager;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class FriendsCircleActivity_ViewBinding implements Unbinder {
    private FriendsCircleActivity target;

    public FriendsCircleActivity_ViewBinding(FriendsCircleActivity target, View source) {
        this.target = target;
        target.containerTab = Utils.findRequiredView(source, R.attr.containerTab, "field 'containerTab'");
        target.tabLayout = (SlidingTabLayout) Utils.findRequiredViewAsType(source, R.attr.tabLayout, "field 'tabLayout'", SlidingTabLayout.class);
        target.viewpager = (NoScrollViewPager) Utils.findRequiredViewAsType(source, R.attr.viewpager, "field 'viewpager'", NoScrollViewPager.class);
    }

    @Override // butterknife.Unbinder
    public void unbind() {
        FriendsCircleActivity target = this.target;
        if (target == null) {
            throw new IllegalStateException("Bindings already cleared.");
        }
        this.target = null;
        target.containerTab = null;
        target.tabLayout = null;
        target.viewpager = null;
    }
}
