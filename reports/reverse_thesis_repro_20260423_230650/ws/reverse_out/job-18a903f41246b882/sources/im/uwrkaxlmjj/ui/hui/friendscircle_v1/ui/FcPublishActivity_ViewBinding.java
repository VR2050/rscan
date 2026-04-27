package im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui;

import android.view.View;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.RelativeLayout;
import butterknife.Unbinder;
import butterknife.internal.DebouncingOnClickListener;
import butterknife.internal.Utils;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class FcPublishActivity_ViewBinding implements Unbinder {
    private FcPublishActivity target;
    private View view7f09008b;
    private View view7f09008c;
    private View view7f090218;

    public FcPublishActivity_ViewBinding(final FcPublishActivity target, View source) {
        this.target = target;
        target.etContent = (EditText) Utils.findRequiredViewAsType(source, R.attr.et_content, "field 'etContent'", EditText.class);
        View view = Utils.findRequiredView(source, R.attr.biv_video, "field 'bivVideo' and method 'onViewClicked'");
        target.bivVideo = (ImageView) Utils.castView(view, R.attr.biv_video, "field 'bivVideo'", ImageView.class);
        this.view7f09008b = view;
        view.setOnClickListener(new DebouncingOnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.FcPublishActivity_ViewBinding.1
            @Override // butterknife.internal.DebouncingOnClickListener
            public void doClick(View p0) {
                target.onViewClicked(p0);
            }
        });
        target.rlContainer = (RelativeLayout) Utils.findRequiredViewAsType(source, R.attr.rl_container, "field 'rlContainer'", RelativeLayout.class);
        View view2 = Utils.findRequiredView(source, R.attr.biv_video_h, "field 'bivVideoH' and method 'onViewClicked'");
        target.bivVideoH = (ImageView) Utils.castView(view2, R.attr.biv_video_h, "field 'bivVideoH'", ImageView.class);
        this.view7f09008c = view2;
        view2.setOnClickListener(new DebouncingOnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.FcPublishActivity_ViewBinding.2
            @Override // butterknife.internal.DebouncingOnClickListener
            public void doClick(View p0) {
                target.onViewClicked(p0);
            }
        });
        target.rvMenu = (RecyclerListView) Utils.findRequiredViewAsType(source, R.attr.rvMenu, "field 'rvMenu'", RecyclerListView.class);
        View view3 = Utils.findRequiredView(source, R.attr.iv_close, "method 'onViewClicked'");
        this.view7f090218 = view3;
        view3.setOnClickListener(new DebouncingOnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.FcPublishActivity_ViewBinding.3
            @Override // butterknife.internal.DebouncingOnClickListener
            public void doClick(View p0) {
                target.onViewClicked(p0);
            }
        });
    }

    @Override // butterknife.Unbinder
    public void unbind() {
        FcPublishActivity target = this.target;
        if (target == null) {
            throw new IllegalStateException("Bindings already cleared.");
        }
        this.target = null;
        target.etContent = null;
        target.bivVideo = null;
        target.rlContainer = null;
        target.bivVideoH = null;
        target.rvMenu = null;
        this.view7f09008b.setOnClickListener(null);
        this.view7f09008b = null;
        this.view7f09008c.setOnClickListener(null);
        this.view7f09008c = null;
        this.view7f090218.setOnClickListener(null);
        this.view7f090218 = null;
    }
}
