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
public class VisualCallReceiveActivity_ViewBinding implements Unbinder {
    private VisualCallReceiveActivity target;
    private View view7f0900cb;
    private View view7f0901a9;
    private View view7f0901aa;
    private View view7f0901ab;
    private View view7f0901ad;
    private View view7f0901b5;
    private View view7f09023f;
    private View view7f09029f;
    private View view7f090669;

    public VisualCallReceiveActivity_ViewBinding(VisualCallReceiveActivity target) {
        this(target, target.getWindow().getDecorView());
    }

    public VisualCallReceiveActivity_ViewBinding(final VisualCallReceiveActivity target, View source) {
        this.target = target;
        View view = Utils.findRequiredView(source, R.attr.img_operate_a, "field 'imgOperateA' and method 'onViewClicked'");
        target.imgOperateA = (ImageView) Utils.castView(view, R.attr.img_operate_a, "field 'imgOperateA'", ImageView.class);
        this.view7f0901a9 = view;
        view.setOnClickListener(new DebouncingOnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.VisualCallReceiveActivity_ViewBinding.1
            @Override // butterknife.internal.DebouncingOnClickListener
            public void doClick(View p0) {
                target.onViewClicked(p0);
            }
        });
        target.linOperateA = (LinearLayout) Utils.findRequiredViewAsType(source, R.attr.lin_operate_a, "field 'linOperateA'", LinearLayout.class);
        target.linOperateB = (LinearLayout) Utils.findRequiredViewAsType(source, R.attr.lin_operate_b, "field 'linOperateB'", LinearLayout.class);
        View view2 = Utils.findRequiredView(source, R.attr.img_operate_c, "field 'imgOperateC' and method 'onViewClicked'");
        target.imgOperateC = (ImageView) Utils.castView(view2, R.attr.img_operate_c, "field 'imgOperateC'", ImageView.class);
        this.view7f0901ab = view2;
        view2.setOnClickListener(new DebouncingOnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.VisualCallReceiveActivity_ViewBinding.2
            @Override // butterknife.internal.DebouncingOnClickListener
            public void doClick(View p0) {
                target.onViewClicked(p0);
            }
        });
        target.linOperateC = (LinearLayout) Utils.findRequiredViewAsType(source, R.attr.lin_operate_c, "field 'linOperateC'", LinearLayout.class);
        target.relVideoUser = (RelativeLayout) Utils.findRequiredViewAsType(source, R.attr.rel_video_user, "field 'relVideoUser'", RelativeLayout.class);
        target.imgVideoUserHead = (BackupImageView) Utils.findRequiredViewAsType(source, R.attr.img_video_user_head, "field 'imgVideoUserHead'", BackupImageView.class);
        target.txtVideoName = (TextView) Utils.findRequiredViewAsType(source, R.attr.txt_video_name, "field 'txtVideoName'", TextView.class);
        target.txtVideoStatus = (ColorTextView) Utils.findRequiredViewAsType(source, R.attr.txt_video_status, "field 'txtVideoStatus'", ColorTextView.class);
        View view3 = Utils.findRequiredView(source, R.attr.img_visualcall, "field 'imgVisualcall' and method 'onViewClicked'");
        target.imgVisualcall = (ImageView) Utils.castView(view3, R.attr.img_visualcall, "field 'imgVisualcall'", ImageView.class);
        this.view7f0901b5 = view3;
        view3.setOnClickListener(new DebouncingOnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.VisualCallReceiveActivity_ViewBinding.3
            @Override // butterknife.internal.DebouncingOnClickListener
            public void doClick(View p0) {
                target.onViewClicked(p0);
            }
        });
        target.imgUserHead = (BackupImageView) Utils.findRequiredViewAsType(source, R.attr.img_user_head, "field 'imgUserHead'", BackupImageView.class);
        target.txtCallName = (TextView) Utils.findRequiredViewAsType(source, R.attr.txt_call_name, "field 'txtCallName'", TextView.class);
        target.txtCallStatus = (ColorTextView) Utils.findRequiredViewAsType(source, R.attr.txt_call_status, "field 'txtCallStatus'", ColorTextView.class);
        target.relVoiceUser = (RelativeLayout) Utils.findRequiredViewAsType(source, R.attr.rel_voice_user, "field 'relVoiceUser'", RelativeLayout.class);
        target.chartContentUserlist = (RecyclerView) Utils.findRequiredViewAsType(source, R.attr.chart_content_userlist, "field 'chartContentUserlist'", RecyclerView.class);
        View view4 = Utils.findRequiredView(source, R.attr.txt_pre_change_to_voice, "field 'txtPreChangeToVoice' and method 'onViewClicked'");
        target.txtPreChangeToVoice = (ColorTextView) Utils.castView(view4, R.attr.txt_pre_change_to_voice, "field 'txtPreChangeToVoice'", ColorTextView.class);
        this.view7f090669 = view4;
        view4.setOnClickListener(new DebouncingOnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.VisualCallReceiveActivity_ViewBinding.4
            @Override // butterknife.internal.DebouncingOnClickListener
            public void doClick(View p0) {
                target.onViewClicked(p0);
            }
        });
        target.txtVisualcallStatus = (ColorTextView) Utils.findRequiredViewAsType(source, R.attr.txt_visualcall_status, "field 'txtVisualcallStatus'", ColorTextView.class);
        target.txtOperateA = (ColorTextView) Utils.findRequiredViewAsType(source, R.attr.txt_operate_a, "field 'txtOperateA'", ColorTextView.class);
        View view5 = Utils.findRequiredView(source, R.attr.img_operate_b, "field 'imgOperateB' and method 'onViewClicked'");
        target.imgOperateB = (ImageView) Utils.castView(view5, R.attr.img_operate_b, "field 'imgOperateB'", ImageView.class);
        this.view7f0901aa = view5;
        view5.setOnClickListener(new DebouncingOnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.VisualCallReceiveActivity_ViewBinding.5
            @Override // butterknife.internal.DebouncingOnClickListener
            public void doClick(View p0) {
                target.onViewClicked(p0);
            }
        });
        target.txtOperateB = (ColorTextView) Utils.findRequiredViewAsType(source, R.attr.txt_operate_b, "field 'txtOperateB'", ColorTextView.class);
        target.txtOperateC = (ColorTextView) Utils.findRequiredViewAsType(source, R.attr.txt_operate_c, "field 'txtOperateC'", ColorTextView.class);
        target.relVisualCallA = (LinearLayout) Utils.findRequiredViewAsType(source, R.attr.rel_visual_call_a, "field 'relVisualCallA'", LinearLayout.class);
        target.linPreRefuse = (LinearLayout) Utils.findRequiredViewAsType(source, R.attr.lin_pre_refuse, "field 'linPreRefuse'", LinearLayout.class);
        View view6 = Utils.findRequiredView(source, R.attr.img_pre_receive, "field 'imgPreReceive' and method 'onViewClicked'");
        target.imgPreReceive = (ImageView) Utils.castView(view6, R.attr.img_pre_receive, "field 'imgPreReceive'", ImageView.class);
        this.view7f0901ad = view6;
        view6.setOnClickListener(new DebouncingOnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.VisualCallReceiveActivity_ViewBinding.6
            @Override // butterknife.internal.DebouncingOnClickListener
            public void doClick(View p0) {
                target.onViewClicked(p0);
            }
        });
        target.linPreReceive = (LinearLayout) Utils.findRequiredViewAsType(source, R.attr.lin_pre_receive, "field 'linPreReceive'", LinearLayout.class);
        target.relVisualCallB = (RelativeLayout) Utils.findRequiredViewAsType(source, R.attr.rel_visual_call_b, "field 'relVisualCallB'", RelativeLayout.class);
        target.rootView = (RelativeLayout) Utils.findRequiredViewAsType(source, R.attr.root_view, "field 'rootView'", RelativeLayout.class);
        View view7 = Utils.findRequiredView(source, R.attr.chart_video_container, "field 'chartVideoContainer' and method 'onViewClicked'");
        target.chartVideoContainer = (DragFrameLayout) Utils.castView(view7, R.attr.chart_video_container, "field 'chartVideoContainer'", DragFrameLayout.class);
        this.view7f0900cb = view7;
        view7.setOnClickListener(new DebouncingOnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.VisualCallReceiveActivity_ViewBinding.7
            @Override // butterknife.internal.DebouncingOnClickListener
            public void doClick(View p0) {
                target.onViewClicked(p0);
            }
        });
        View view8 = Utils.findRequiredView(source, R.attr.ll_big_window, "field 'llBigWindow' and method 'onViewClicked'");
        target.llBigWindow = (LinearLayout) Utils.castView(view8, R.attr.ll_big_window, "field 'llBigWindow'", LinearLayout.class);
        this.view7f09029f = view8;
        view8.setOnClickListener(new DebouncingOnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.VisualCallReceiveActivity_ViewBinding.8
            @Override // butterknife.internal.DebouncingOnClickListener
            public void doClick(View p0) {
                target.onViewClicked(p0);
            }
        });
        target.chrVisualcallTime = (Chronometer) Utils.findRequiredViewAsType(source, R.attr.chr_visualcall_time, "field 'chrVisualcallTime'", Chronometer.class);
        target.txtTip = (TextView) Utils.findRequiredViewAsType(source, R.attr.txt_tip, "field 'txtTip'", TextView.class);
        View view9 = Utils.findRequiredView(source, R.attr.iv_pre_refuse, "field 'ivPreRefuse' and method 'onViewClicked'");
        target.ivPreRefuse = (ImageView) Utils.castView(view9, R.attr.iv_pre_refuse, "field 'ivPreRefuse'", ImageView.class);
        this.view7f09023f = view9;
        view9.setOnClickListener(new DebouncingOnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.VisualCallReceiveActivity_ViewBinding.9
            @Override // butterknife.internal.DebouncingOnClickListener
            public void doClick(View p0) {
                target.onViewClicked(p0);
            }
        });
        target.txtMask = (TextView) Utils.findRequiredViewAsType(source, R.attr.txt_mask, "field 'txtMask'", TextView.class);
        target.llBigRemoteView = (LinearLayout) Utils.findRequiredViewAsType(source, R.attr.ll_big_remote_view, "field 'llBigRemoteView'", LinearLayout.class);
        target.llSmallRemoteView = (LinearLayout) Utils.findRequiredViewAsType(source, R.attr.ll_small_remote_view, "field 'llSmallRemoteView'", LinearLayout.class);
    }

    @Override // butterknife.Unbinder
    public void unbind() {
        VisualCallReceiveActivity target = this.target;
        if (target == null) {
            throw new IllegalStateException("Bindings already cleared.");
        }
        this.target = null;
        target.imgOperateA = null;
        target.linOperateA = null;
        target.linOperateB = null;
        target.imgOperateC = null;
        target.linOperateC = null;
        target.relVideoUser = null;
        target.imgVideoUserHead = null;
        target.txtVideoName = null;
        target.txtVideoStatus = null;
        target.imgVisualcall = null;
        target.imgUserHead = null;
        target.txtCallName = null;
        target.txtCallStatus = null;
        target.relVoiceUser = null;
        target.chartContentUserlist = null;
        target.txtPreChangeToVoice = null;
        target.txtVisualcallStatus = null;
        target.txtOperateA = null;
        target.imgOperateB = null;
        target.txtOperateB = null;
        target.txtOperateC = null;
        target.relVisualCallA = null;
        target.linPreRefuse = null;
        target.imgPreReceive = null;
        target.linPreReceive = null;
        target.relVisualCallB = null;
        target.rootView = null;
        target.chartVideoContainer = null;
        target.llBigWindow = null;
        target.chrVisualcallTime = null;
        target.txtTip = null;
        target.ivPreRefuse = null;
        target.txtMask = null;
        target.llBigRemoteView = null;
        target.llSmallRemoteView = null;
        this.view7f0901a9.setOnClickListener(null);
        this.view7f0901a9 = null;
        this.view7f0901ab.setOnClickListener(null);
        this.view7f0901ab = null;
        this.view7f0901b5.setOnClickListener(null);
        this.view7f0901b5 = null;
        this.view7f090669.setOnClickListener(null);
        this.view7f090669 = null;
        this.view7f0901aa.setOnClickListener(null);
        this.view7f0901aa = null;
        this.view7f0901ad.setOnClickListener(null);
        this.view7f0901ad = null;
        this.view7f0900cb.setOnClickListener(null);
        this.view7f0900cb = null;
        this.view7f09029f.setOnClickListener(null);
        this.view7f09029f = null;
        this.view7f09023f.setOnClickListener(null);
        this.view7f09023f = null;
    }
}
