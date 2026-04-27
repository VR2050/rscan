package im.uwrkaxlmjj.ui.hui.packet.bean;

import im.uwrkaxlmjj.javaBean.hongbao.UnifyBean;

/* JADX INFO: loaded from: classes5.dex */
public class RepacketRequest extends UnifyBean {
    private String fixedAmount;
    private String grantType;
    private String groups;
    private String groupsName;
    private Integer number;
    private String redType;

    public void setRedType(String redType) {
        this.redType = redType;
    }

    public void setGrantType(String grantType) {
        this.grantType = grantType;
    }

    public void setGroups(String groups) {
        this.groups = groups;
    }

    public void setGroupsName(String groupsName) {
        this.groupsName = groupsName;
    }

    public void setFixedAmount(String fixedAmount) {
        this.fixedAmount = fixedAmount;
    }

    public void setNumber(Integer number) {
        this.number = number;
    }
}
