package im.uwrkaxlmjj.javaBean.fc;

import com.bjz.comm.net.bean.RespFcListBean;
import com.litesuits.orm.db.annotation.PrimaryKey;
import com.litesuits.orm.db.annotation.Table;
import com.litesuits.orm.db.enums.AssignType;
import java.io.Serializable;

/* JADX INFO: loaded from: classes2.dex */
@Table("fclist_user")
public class ResponseFclistBeanUser implements Serializable {

    @PrimaryKey(AssignType.BY_MYSELF)
    private long ForumID;
    private RespFcListBean data;
    private boolean isUser;

    public RespFcListBean getData() {
        return this.data;
    }

    public long getForumID() {
        return this.ForumID;
    }

    public void setForumID(long forumID) {
        this.ForumID = forumID;
    }

    public void setData(RespFcListBean data) {
        this.data = data;
    }

    public boolean isUser() {
        return this.isUser;
    }

    public void setUser(boolean user) {
        this.isUser = user;
    }
}
