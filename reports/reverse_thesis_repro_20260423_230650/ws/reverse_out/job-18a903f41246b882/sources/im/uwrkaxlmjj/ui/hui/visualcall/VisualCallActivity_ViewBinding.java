package im.uwrkaxlmjj.ui.hui.visualcall;

import android.view.View;
import android.widget.Chronometer;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import android.widget.TextView;
import androidx.recyclerview.widget.RecyclerView;
import butterknife.Unbinder;
import butterknife.internal.DebouncingOnClickListener;
import butterknife.internal.Utils;
import im.uwrkaxlmjj.ui.components.BackupImageView;
import im.uwrkaxlmjj.ui.components.ColorTextView;
import im.uwrkaxlmjj.ui.hviews.DragFrameLayout;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class VisualCallActivity_ViewBinding implements Unbinder {
    private VisualCallActivity target;
    private View view7f0900cb;
    private View view7f0901a9;
    private View view7f0901aa;
    private View view7f0901ab;
    private View view7f0901b5;
    private View view7f09029f;
    private View view7f090669;

    public VisualCallActivity_ViewBinding(VisualCallActivity target) {
        this(target, target.getWindow().getDecorView());
    }

    public VisualCallActivity_ViewBinding(final VisualCallActivity target, View source) {
        this.target = target;
        View view = Utils.findRequiredView(source, R.attr.img_operate_a, "field 'img_operate_a' and method 'onclick'");
        target.img_operate_a = (ImageView) Utils.castView(view, R.attr.img_operate_a, "field 'img_operate_a'", ImageView.class);
        this.view7f0901a9 = view;
        view.setOnClickListener(new DebouncingOnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.VisualCallActivity_ViewBinding.1
            @Override // butterknife.internal.DebouncingOnClickListener
            public void doClick(View p0) {
                target.onclick(p0);
            }
        });
        target.lin_operate_a = (LinearLayout) Utils.findRequiredViewAsType(source, R.attr.lin_operate_a, "field 'lin_operate_a'", LinearLayout.class);
        target.txt_operate_a = (ColorTextView) Utils.findRequiredViewAsType(source, R.attr.txt_operate_a, "field 'txt_operate_a'", ColorTextView.class);
        View view2 = Utils.findRequiredView(source, R.attr.img_operate_b, "field 'img_operate_b' and method 'onclick'");
        target.img_operate_b = (ImageView) Utils.castView(view2, R.attr.img_operate_b, "field 'img_operate_b'", ImageView.class);
        this.view7f0901aa = view2;
        view2.setOnClickListener(new DebouncingOnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.VisualCallActivity_ViewBinding.2
            @Override // butterknife.internal.DebouncingOnClickListener
            public void doClick(View p0) {
                target.onclick(p0);
            }
        });
        target.lin_operate_b = (LinearLayout) Utils.findRequiredViewAsType(source, R.attr.lin_operate_b, "field 'lin_operate_b'", LinearLayout.class);
        target.txt_operate_b = (ColorTextView) Utils.findRequiredViewAsType(source, R.attr.txt_operate_b, "field 'txt_operate_b'", ColorTextView.class);
        View view3 = Utils.findRequiredView(source, R.attr.img_operate_c, "field 'img_operate_c' and method 'onclick'");
        target.img_operate_c = (ImageView) Utils.castView(view3, R.attr.img_operate_c, "field 'img_operate_c'", ImageView.class);
        this.view7f0901ab = view3;
        view3.setOnClickListener(new DebouncingOnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.VisualCallActivity_ViewBinding.3
            @Override // butterknife.internal.DebouncingOnClickListener
            public void doClick(View p0) {
                target.onclick(p0);
            }
        });
        target.lin_operate_c = (LinearLayout) Utils.findRequiredViewAsType(source, R.attr.lin_operate_c, "field 'lin_operate_c'", LinearLayout.class);
        target.txt_operate_c = (ColorTextView) Utils.findRequiredViewAsType(source, R.attr.txt_operate_c, "field 'txt_operate_c'", ColorTextView.class);
        target.rel_video_user = (RelativeLayout) Utils.findRequiredViewAsType(source, R.attr.rel_video_user, "field 'rel_video_user'", RelativeLayout.class);
        target.rel_voice_user = (RelativeLayout) Utils.findRequiredViewAsType(source, R.attr.rel_voice_user, "field 'rel_voice_user'", RelativeLayout.class);
        target.rel_visual_call_b = (RelativeLayout) Utils.findRequiredViewAsType(source, R.attr.rel_visual_call_b, "field 'rel_visual_call_b'", RelativeLayout.class);
        target.img_pre_receive = (ImageView) Utils.findRequiredViewAsType(source, R.attr.img_pre_receive, "field 'img_pre_receive'", ImageView.class);
        target.rel_visual_call_a = (LinearLayout) Utils.findRequiredViewAsType(source, R.attr.rel_visual_call_a, "field 'rel_visual_call_a'", LinearLayout.class);
        View view4 = Utils.findRequiredView(source, R.attr.txt_pre_change_to_voice, "field 'txt_pre_change_to_voice' and method 'onclick'");
        target.txt_pre_change_to_voice = (TextView) Utils.castView(view4, R.attr.txt_pre_change_to_voice, "field 'txt_pre_change_to_voice'", TextView.class);
        this.view7f090669 = view4;
        view4.setOnClickListener(new DebouncingOnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.VisualCallActivity_ViewBinding.4
            @Override // butterknife.internal.DebouncingOnClickListener
            public void doClick(View p0) {
                target.onclick(p0);
            }
        });
        target.chartUserListView = (RecyclerView) Utils.findRequiredViewAsType(source, R.attr.chart_content_userlist, "field 'chartUserListView'", RecyclerView.class);
        View view5 = Utils.findRequiredView(source, R.attr.chart_video_container, "field 'chart_video_container' and method 'onclick'");
        target.chart_video_container = (DragFrameLayout) Utils.castView(view5, R.attr.chart_video_container, "field 'chart_video_container'", DragFrameLayout.class);
        this.view7f0900cb = view5;
        view5.setOnClickListener(new DebouncingOnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.VisualCallActivity_ViewBinding.5
            @Override // butterknife.internal.DebouncingOnClickListener
            public void doClick(View p0) {
                target.onclick(p0);
            }
        });
        target.txtTip = (TextView) Utils.findRequiredViewAsType(source, R.attr.txt_tip, "field 'txtTip'", TextView.class);
        target.chrVisualcallTime = (Chronometer) Utils.findRequiredViewAsType(source, R.attr.chr_visualcall_time, "field 'chrVisualcallTime'", Chronometer.class);
        target.txtVisualcallStatus = (ColorTextView) Utils.findRequiredViewAsType(source, R.attr.txt_visualcall_status, "field 'txtVisualcallStatus'", ColorTextView.class);
        View view6 = Utils.findRequiredView(source, R.attr.ll_big_window, "field 'llBigWindow' and method 'onclick'");
        target.llBigWindow = (LinearLayout) Utils.castView(view6, R.attr.ll_big_window, "field 'llBigWindow'", LinearLayout.class);
        this.view7f09029f = view6;
        view6.setOnClickListener(new DebouncingOnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.VisualCallActivity_ViewBinding.6
            @Override // butterknife.internal.DebouncingOnClickListener
            public void doClick(View p0) {
                target.onclick(p0);
            }
        });
        target.imgVideoUserHead = (BackupImageView) Utils.findRequiredViewAsType(source, R.attr.img_video_user_head, "field 'imgVideoUserHead'", BackupImageView.class);
        target.imgUserHead = (BackupImageView) Utils.findRequiredViewAsType(source, R.attr.img_user_head, "field 'imgUserHead'", BackupImageView.class);
        target.txtVideoName = (TextView) Utils.findRequiredViewAsType(source, R.attr.txt_video_name, "field 'txtVideoName'", TextView.class);
        target.txtCallName = (TextView) Utils.findRequiredViewAsType(source, R.attr.txt_call_name, "field 'txtCallName'", TextView.class);
        target.txtVideoStatus = (ColorTextView) Utils.findRequiredViewAsType(source, R.attr.txt_video_status, "field 'txtVideoStatus'", ColorTextView.class);
        target.txtCallStatus = (ColorTextView) Utils.findRequiredViewAsType(source, R.attr.txt_call_status, "field 'txtCallStatus'", ColorTextView.class);
        target.llBigRemoteView = (LinearLayout) Utils.findRequiredViewAsType(source, R.attr.ll_big_remote_view, "field 'llBigRemoteView'", LinearLayout.class);
        target.llSmallRemoteView = (LinearLayout) Utils.findRequiredViewAsType(source, R.attr.ll_small_remote_view, "field 'llSmallRemoteView'", LinearLayout.class);
        View view7 = Utils.findRequiredView(source, R.attr.img_visualcall, "field 'imgVisualcall' and method 'onclick'");
        target.imgVisualcall = (ImageView) Utils.castView(view7, R.attr.img_visualcall, "field 'imgVisualcall'", ImageView.class);
        this.view7f0901b5 = view7;
        view7.setOnClickListener(new DebouncingOnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.VisualCallActivity_ViewBinding.7
            @Override // butterknife.internal.DebouncingOnClickListener
            public void doClick(View p0) {
                target.onclick(p0);
            }
        });
    }

    @Override // butterknife.Unbinder
    public void unbind() {
        VisualCallActivity target = this.target;
        if (target == null) {
            throw new IllegalStateException("Bindings already cleared.");
        }
        this.target = null;
        target.img_operate_a = null;
        target.lin_operate_a = null;
        target.txt_operate_a = null;
        target.img_operate_b = null;
        target.lin_operate_b = null;
        target.txt_operate_b = null;
        target.img_operate_c = null;
        target.lin_operate_c = null;
        target.txt_operate_c = null;
        target.rel_video_user = null;
        target.rel_voice_user = null;
        target.rel_visual_call_b = null;
        target.img_pre_receive = null;
        target.rel_visual_call_a = null;
        target.txt_pre_change_to_voice = null;
        target.chartUserListView = null;
        target.chart_video_container = null;
        target.txtTip = null;
        target.chrVisualcallTime = null;
        target.txtVisualcallStatus = null;
        target.llBigWindow = null;
        target.imgVideoUserHead = null;
        target.imgUserHead = null;
        target.txtVideoName = null;
        target.txtCallName = null;
        target.txtVideoStatus = null;
        target.txtCallStatus = null;
        target.llBigRemoteView = null;
        target.llSmallRemoteView = null;
        target.imgVisualcall = null;
        this.view7f0901a9.setOnClickListener(null);
        this.view7f0901a9 = null;
        this.view7f0901aa.setOnClickListener(null);
        this.view7f0901aa = null;
        this.view7f0901ab.setOnClickListener(null);
        this.view7f0901ab = null;
        this.view7f090669.setOnClickListener(null);
        this.view7f090669 = null;
        this.view7f0900cb.setOnClickListener(null);
        this.view7f0900cb = null;
        this.view7f09029f.setOnClickListener(null);
        this.view7f09029f = null;
        this.view7f0901b5.setOnClickListener(null);
        this.view7f0901b5 = null;
    }
}
