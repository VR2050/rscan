package im.uwrkaxlmjj.javaBean.fc;

import com.bjz.comm.net.bean.RespFcListBean;
import com.litesuits.orm.db.annotation.Table;

/* JADX INFO: loaded from: classes2.dex */
@Table("fc_list_followed")
public class FollowedFcListBean extends RespFcListBean {
    public FollowedFcListBean() {
    }

    public FollowedFcListBean(RespFcListBean response) {
        super(response);
    }
}
