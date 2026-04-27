package im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.expandTextView.model;

import com.bjz.comm.net.expandViewModel.ExpandableStatusFix;
import com.bjz.comm.net.expandViewModel.StatusType;

/* JADX INFO: loaded from: classes5.dex */
public class ViewModelWithFlag implements ExpandableStatusFix {
    private String content;
    private StatusType status;

    public ViewModelWithFlag(String content) {
        this.content = content;
    }

    public String getContent() {
        return this.content;
    }

    public void setContent(String content) {
        this.content = content;
    }

    @Override // com.bjz.comm.net.expandViewModel.ExpandableStatusFix
    public void setStatusType(StatusType statusType) {
        this.status = statusType;
    }

    @Override // com.bjz.comm.net.expandViewModel.ExpandableStatusFix
    public StatusType getStatusType() {
        return this.status;
    }
}
