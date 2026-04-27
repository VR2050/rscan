package im.uwrkaxlmjj.ui.hui.friendscircle_v1.base;

import android.animation.ObjectAnimator;
import android.content.Context;
import android.view.View;
import androidx.recyclerview.widget.RecyclerView;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;

/* JADX INFO: loaded from: classes5.dex */
public abstract class CommFcActivity extends BaseFcActivity {
    protected RecyclerView.LayoutManager layoutManager;

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.BaseFcActivity, im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        super.createView(context);
        return this.fragmentView;
    }

    public void hideTitle(View rootView) {
        ObjectAnimator animator = ObjectAnimator.ofFloat(rootView, "translationY", 0.0f, -ActionBar.getCurrentActionBarHeight());
        animator.setDuration(300L);
        animator.start();
        this.actionBar.setVisibility(4);
    }

    public void showTitle(View rootView) {
        ObjectAnimator animator = ObjectAnimator.ofFloat(rootView, "translationY", -ActionBar.getCurrentActionBarHeight(), 0.0f);
        animator.start();
        this.actionBar.setVisibility(0);
    }
}
