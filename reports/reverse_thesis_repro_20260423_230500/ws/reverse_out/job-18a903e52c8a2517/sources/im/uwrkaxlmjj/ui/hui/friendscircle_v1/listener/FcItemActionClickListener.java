package im.uwrkaxlmjj.ui.hui.friendscircle_v1.listener;

import android.view.View;
import com.bjz.comm.net.bean.RespFcListBean;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;

/* JADX INFO: loaded from: classes5.dex */
public interface FcItemActionClickListener {
    void onAction(View view, int i, int i2, Object obj);

    void onPresentFragment(BaseFragment baseFragment);

    void onReplyClick(View view, String str, RespFcListBean respFcListBean, int i, int i2, boolean z);
}
